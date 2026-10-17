//! Aegis TI — defensive ETW / kernel tracing collector.
//! Observational only: process/image/network/DNS telemetry → JSONL evidence events.

use chrono::Utc;
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Serialize, Clone)]
struct Entity {
    kind: String,
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    attrs: Option<HashMap<String, serde_json::Value>>,
}

#[derive(Serialize, Clone)]
struct Edge {
    src: String,
    dst: String,
    rel: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence: Option<f64>,
}

#[derive(Serialize, Clone)]
struct Event {
    ts: String,
    agent: String,
    host_id: String,
    #[serde(rename = "type")]
    event_type: String,
    severity: String,
    entities: Vec<Entity>,
    edges: Vec<Edge>,
    raw: serde_json::Value,
}

fn main() {
    let host_id = env::var("AEGIS_HOST_ID").unwrap_or_else(|_| hostname());
    let host_id = if host_id.len() > 128 {
        host_id[..128].to_string()
    } else {
        host_id
    };
    let duration_secs: u64 = env::var("AEGIS_ETW_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6)
        .clamp(2, 30);

    #[cfg(windows)]
    {
        let events = collect_etw(&host_id, duration_secs);
        for e in events {
            if let Ok(line) = serde_json::to_string(&e) {
                println!("{line}");
            }
        }
    }

    #[cfg(not(windows))]
    {
        let _ = duration_secs;
        let e = Event {
            ts: Utc::now().to_rfc3339(),
            agent: "rust-etw".into(),
            host_id,
            event_type: "etw.unavailable".into(),
            severity: "info".into(),
            entities: vec![],
            edges: vec![],
            raw: serde_json::json!({
                "reason": "ETW is Windows-only",
                "how": "Kernel/user ETW providers require a Windows host agent"
            }),
        };
        if let Ok(line) = serde_json::to_string(&e) {
            println!("{line}");
        }
    }
}

fn hostname() -> String {
    env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "local-host".into())
}

#[cfg(windows)]
mod win {
    use super::*;
    use ferrisetw::parser::Parser;
    use ferrisetw::provider::Provider;
    use ferrisetw::schema_locator::SchemaLocator;
    use ferrisetw::trace::UserTrace;
    use ferrisetw::EventRecord;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    pub fn is_elevated() -> bool {
        unsafe {
            let mut token = windows::Win32::Foundation::HANDLE::default();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
                return false;
            }
            let mut elevation = TOKEN_ELEVATION::default();
            let mut ret_len = 0u32;
            let ok = GetTokenInformation(
                token,
                TokenElevation,
                Some(&mut elevation as *mut _ as *mut _),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut ret_len,
            );
            let _ = CloseHandle(token);
            ok.is_ok() && elevation.TokenIsElevated != 0
        }
    }

    pub fn collect_etw(host_id: &str, duration_secs: u64) -> Vec<Event> {
        let elevated = is_elevated();
        let sink: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));
        let host = host_id.to_string();

        // Status event always emitted
        {
            let mut g = sink.lock().unwrap();
            g.push(Event {
                ts: Utc::now().to_rfc3339(),
                agent: "rust-etw".into(),
                host_id: host.clone(),
                event_type: "etw.session".into(),
                severity: if elevated { "info".into() } else { "medium".into() },
                entities: vec![Entity {
                    kind: "host".into(),
                    id: host.clone(),
                    label: Some(host.clone()),
                    attrs: Some(HashMap::from([
                        ("etw_elevated".into(), serde_json::json!(elevated)),
                        ("duration_secs".into(), serde_json::json!(duration_secs)),
                    ])),
                }],
                edges: vec![],
                raw: serde_json::json!({
                    "elevated": elevated,
                    "providers": [
                        "Microsoft-Windows-Kernel-Process",
                        "Microsoft-Windows-DNS-Client",
                        "Microsoft-Windows-TCPIP"
                    ],
                    "how": "Real-time ETW UserTrace session (defensive observation)",
                    "note": if elevated {
                        "Running elevated — kernel-process provider enabled"
                    } else {
                        "Not elevated — ETW may be incomplete; run gateway/agent as Administrator for full kernel tracing"
                    }
                }),
            });
        }

        let sink_proc = sink.clone();
        let host_proc = host.clone();
        let process_provider = Provider::by_guid("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716") // Kernel-Process
            .add_callback(move |record: &EventRecord, schema_locator: &SchemaLocator| {
                on_kernel_process(record, schema_locator, &sink_proc, &host_proc);
            })
            .build();

        let sink_dns = sink.clone();
        let host_dns = host.clone();
        let dns_provider = Provider::by_guid("1c95126e-7eea-49a9-a3fe-a378b03ddb4d") // DNS-Client
            .add_callback(move |record: &EventRecord, schema_locator: &SchemaLocator| {
                on_dns(record, schema_locator, &sink_dns, &host_dns);
            })
            .build();

        let sink_tcp = sink.clone();
        let host_tcp = host.clone();
        let tcp_provider = Provider::by_guid("2f07e2ee-15db-40f1-90ef-9d7ba282188a") // TCPIP
            .add_callback(move |record: &EventRecord, schema_locator: &SchemaLocator| {
                on_tcpip(record, schema_locator, &sink_tcp, &host_tcp);
            })
            .build();

        let session_name = format!("AegisTI-ETW-{}", std::process::id());
        let trace = match UserTrace::new()
            .named(session_name)
            .enable(process_provider)
            .enable(dns_provider)
            .enable(tcp_provider)
            .start_and_process()
        {
            Ok(t) => t,
            Err(err) => {
                let mut g = sink.lock().unwrap();
                g.push(Event {
                    ts: Utc::now().to_rfc3339(),
                    agent: "rust-etw".into(),
                    host_id: host,
                    event_type: "etw.error".into(),
                    severity: "high".into(),
                    entities: vec![],
                    edges: vec![],
                    raw: serde_json::json!({
                        "error": format!("{err:?}"),
                        "how": "ETW session failed to start — often requires Administrator",
                        "elevated": elevated
                    }),
                });
                return g.clone();
            }
        };

        // Generate a little local activity so Process/DNS events appear during short windows
        let _ = std::process::Command::new("cmd")
            .args(["/C", "echo aegis-etw-probe>nul"])
            .output();
        let _ = std::net::TcpStream::connect_timeout(
            &"1.1.1.1:53".parse().unwrap(),
            Duration::from_millis(400),
        );

        std::thread::sleep(Duration::from_secs(duration_secs));
        let _ = trace.stop();

        let mut events = sink.lock().unwrap().clone();
        // Cap flood
        if events.len() > 400 {
            let status: Vec<_> = events
                .iter()
                .filter(|e| e.event_type.starts_with("etw.session") || e.event_type == "etw.error")
                .cloned()
                .collect();
            events.truncate(400);
            for s in status {
                if !events.iter().any(|e| e.event_type == s.event_type) {
                    events.insert(0, s);
                }
            }
        }
        events
    }

    fn push_capped(sink: &Arc<Mutex<Vec<Event>>>, event: Event) {
        if let Ok(mut g) = sink.lock() {
            if g.len() < 450 {
                g.push(event);
            }
        }
    }

    fn parse_str(parser: &Parser<'_, '_>, names: &[&str]) -> Option<String> {
        for n in names {
            if let Ok(v) = parser.try_parse::<String>(n) {
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
        None
    }

    fn parse_u32(parser: &Parser<'_, '_>, names: &[&str]) -> Option<u32> {
        for n in names {
            if let Ok(v) = parser.try_parse::<u32>(n) {
                return Some(v);
            }
            if let Ok(v) = parser.try_parse::<u64>(n) {
                return Some(v as u32);
            }
        }
        None
    }

    fn on_kernel_process(
        record: &EventRecord,
        schema_locator: &SchemaLocator,
        sink: &Arc<Mutex<Vec<Event>>>,
        host_id: &str,
    ) {
        let schema = match schema_locator.event_schema(record) {
            Ok(s) => s,
            Err(_) => return,
        };
        let parser = Parser::create(record, &schema);
        let eid = record.event_id();
        // 1 ProcessStart, 2 ProcessStop, 5 ImageLoad (common Kernel-Process IDs)
        let (etype, sev, action) = match eid {
            1 => ("etw.process.start", "info", "starts"),
            2 => ("etw.process.stop", "info", "stops"),
            5 => ("etw.image.load", "low", "loads"),
            _ => ("etw.kernel.process", "info", "observed"),
        };

        let image = parse_str(
            &parser,
            &["ImageName", "ImageFileName", "FileName", "ProcessName"],
        )
        .unwrap_or_else(|| format!("event:{eid}"));
        let pid = parse_u32(&parser, &["ProcessID", "ProcessId", "PID"]).unwrap_or(0);
        let ppid = parse_u32(&parser, &["ParentProcessID", "ParentProcessId", "PPID"]).unwrap_or(0);

        let proc_id = if pid > 0 {
            format!("pid:{pid}")
        } else {
            format!("etw:proc:{eid}:{}", image.chars().take(40).collect::<String>())
        };
        let short = image.rsplit(['\\', '/']).next().unwrap_or(&image).to_string();

        let mut ents = vec![
            Entity {
                kind: "host".into(),
                id: host_id.into(),
                label: Some(host_id.into()),
                attrs: None,
            },
            Entity {
                kind: "process".into(),
                id: proc_id.clone(),
                label: Some(short.clone()),
                attrs: Some(HashMap::from([
                    ("pid".into(), serde_json::json!(pid)),
                    ("ppid".into(), serde_json::json!(ppid)),
                    ("image".into(), serde_json::json!(image)),
                    ("etw_event_id".into(), serde_json::json!(eid)),
                    ("source".into(), serde_json::json!("etw.kernel-process")),
                ])),
            },
        ];
        let mut edges = vec![Edge {
            src: host_id.into(),
            dst: proc_id.clone(),
            rel: "observed_as".into(),
            confidence: Some(0.9),
        }];
        if ppid > 0 && eid == 1 {
            let parent = format!("pid:{ppid}");
            ents.push(Entity {
                kind: "process".into(),
                id: parent.clone(),
                label: Some(format!("pid {ppid}")),
                attrs: Some(HashMap::from([("pid".into(), serde_json::json!(ppid))])),
            });
            edges.push(Edge {
                src: parent,
                dst: proc_id.clone(),
                rel: "spawns".into(),
                confidence: Some(0.95),
            });
        }
        if eid == 5 {
            let img_id = format!("image:{}", short);
            ents.push(Entity {
                kind: "asset".into(),
                id: img_id.clone(),
                label: Some(short.clone()),
                attrs: Some(HashMap::from([
                    ("kind".into(), serde_json::json!("image")),
                    ("path".into(), serde_json::json!(image)),
                ])),
            });
            edges.push(Edge {
                src: proc_id,
                dst: img_id,
                rel: "loads".into(),
                confidence: Some(0.85),
            });
        }

        let interesting = eid == 1
            || eid == 5
            || short.to_lowercase().contains("powershell")
            || short.to_lowercase().contains("cmd")
            || short.to_lowercase().contains("wscript")
            || short.to_lowercase().contains("rundll32");
        if !interesting && eid != 1 {
            return;
        }

        push_capped(
            sink,
            Event {
                ts: Utc::now().to_rfc3339(),
                agent: "rust-etw".into(),
                host_id: host_id.into(),
                event_type: etype.into(),
                severity: sev.into(),
                entities: ents,
                edges,
                raw: serde_json::json!({
                    "provider": "Microsoft-Windows-Kernel-Process",
                    "event_id": eid,
                    "action": action,
                    "image": image,
                    "pid": pid,
                    "ppid": ppid,
                    "how": "ETW Kernel-Process provider (real-time)",
                    "layer": "kernel"
                }),
            },
        );
    }

    fn on_dns(
        record: &EventRecord,
        schema_locator: &SchemaLocator,
        sink: &Arc<Mutex<Vec<Event>>>,
        host_id: &str,
    ) {
        let schema = match schema_locator.event_schema(record) {
            Ok(s) => s,
            Err(_) => return,
        };
        let parser = Parser::create(record, &schema);
        let eid = record.event_id();
        let query = match parse_str(
            &parser,
            &["QueryName", "Query", "Name", "HostName", "DomainName"],
        ) {
            Some(q) => q,
            None => return,
        };
        if query.is_empty() || query.len() > 253 {
            return;
        }
        let qid = format!("dns:{}", query.to_lowercase());
        push_capped(
            sink,
            Event {
                ts: Utc::now().to_rfc3339(),
                agent: "rust-etw".into(),
                host_id: host_id.into(),
                event_type: "etw.dns.query".into(),
                severity: "info".into(),
                entities: vec![
                    Entity {
                        kind: "host".into(),
                        id: host_id.into(),
                        label: Some(host_id.into()),
                        attrs: None,
                    },
                    Entity {
                        kind: "asset".into(),
                        id: qid.clone(),
                        label: Some(query.clone()),
                        attrs: Some(HashMap::from([
                            ("kind".into(), serde_json::json!("dns_query")),
                            ("etw_event_id".into(), serde_json::json!(eid)),
                        ])),
                    },
                ],
                edges: vec![Edge {
                    src: host_id.into(),
                    dst: qid,
                    rel: "connects".into(),
                    confidence: Some(0.7),
                }],
                raw: serde_json::json!({
                    "provider": "Microsoft-Windows-DNS-Client",
                    "event_id": eid,
                    "query": query,
                    "how": "ETW DNS-Client provider",
                    "layer": "usermode",
                    "function": "dns"
                }),
            },
        );
    }

    fn on_tcpip(
        record: &EventRecord,
        schema_locator: &SchemaLocator,
        sink: &Arc<Mutex<Vec<Event>>>,
        host_id: &str,
    ) {
        let schema = match schema_locator.event_schema(record) {
            Ok(s) => s,
            Err(_) => return,
        };
        let parser = Parser::create(record, &schema);
        let eid = record.event_id();
        // Keep only a subset — TCPIP is chatty
        if !matches!(eid, 10 | 11 | 12 | 15 | 16 | 17 | 18 | 26 | 1024 | 1025 | 1026 | 1027) {
            return;
        }
        let dest = parse_str(
            &parser,
            &[
                "DestAddress",
                "DestinationAddress",
                "daddr",
                "RemoteAddress",
                "Address",
            ],
        );
        let dport = parse_u32(
            &parser,
            &["DestPort", "DestinationPort", "dport", "RemotePort", "Port"],
        );
        let pid = parse_u32(&parser, &["PID", "ProcessId", "ProcessID"]).unwrap_or(0);
        if dest.is_none() && dport.is_none() {
            return;
        }
        let label = format!(
            "{}:{}",
            dest.clone().unwrap_or_else(|| "*".into()),
            dport.unwrap_or(0)
        );
        let nid = format!("net:{}", label);
        let mut ents = vec![
            Entity {
                kind: "host".into(),
                id: host_id.into(),
                label: Some(host_id.into()),
                attrs: None,
            },
            Entity {
                kind: "port".into(),
                id: nid.clone(),
                label: Some(label),
                attrs: Some(HashMap::from([
                    ("remote".into(), serde_json::json!(dest)),
                    ("port".into(), serde_json::json!(dport)),
                    ("etw_event_id".into(), serde_json::json!(eid)),
                    ("source".into(), serde_json::json!("etw.tcpip")),
                ])),
            },
        ];
        let mut edges = vec![Edge {
            src: host_id.into(),
            dst: nid.clone(),
            rel: "connects".into(),
            confidence: Some(0.75),
        }];
        if pid > 0 {
            let proc_id = format!("pid:{pid}");
            ents.push(Entity {
                kind: "process".into(),
                id: proc_id.clone(),
                label: Some(format!("pid {pid}")),
                attrs: Some(HashMap::from([("pid".into(), serde_json::json!(pid))])),
            });
            edges.push(Edge {
                src: proc_id,
                dst: nid,
                rel: "connects".into(),
                confidence: Some(0.8),
            });
        }
        push_capped(
            sink,
            Event {
                ts: Utc::now().to_rfc3339(),
                agent: "rust-etw".into(),
                host_id: host_id.into(),
                event_type: "etw.network.flow".into(),
                severity: "info".into(),
                entities: ents,
                edges,
                raw: serde_json::json!({
                    "provider": "Microsoft-Windows-TCPIP",
                    "event_id": eid,
                    "dest": dest,
                    "remote_ip": dest,
                    "dport": dport,
                    "remote_port": dport,
                    "pid": pid,
                    "how": "ETW TCPIP provider (kernel networking path)",
                    "layer": "kernel",
                    "function": "network"
                }),
            },
        );
    }
}

#[cfg(windows)]
fn collect_etw(host_id: &str, duration_secs: u64) -> Vec<Event> {
    win::collect_etw(host_id, duration_secs)
}
