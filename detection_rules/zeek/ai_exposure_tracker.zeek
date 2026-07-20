# =============================================================================
# ai_exposure_tracker.zeek - AI Service Exposure Tracking Script for Zeek
# Version: 1.0.0
# Date: 2026-07-20
# License: MIT License
# =============================================================================
#
# DESCRIPTION:
# This Zeek script tracks AI service exposure over time, generating persistence
# reports and trend analysis for security monitoring.
#
# USAGE:
#   # Continuous tracking
#   zeek ai_exposure_tracker.zeek -i eth0
#
#   # Analyze historical data
#   zeek ai_exposure_tracker.zeek -r historical.pcap
#
# OUTPUT:
#   - ai_exposure_daily.log: Daily exposure snapshot
#   - ai_exposure_changes.log: Exposure changes (new/disappeared)
#   - ai_exposure_trends.log: Trend analysis
#
# REQUIREMENTS:
#   - Zeek 4.0+
#   - SQLite support (zeek-sqlite plugin) or file-based storage
#
# =============================================================================

@load base/frameworks/logging
@load base/frameworks/sumstats
@load base/protocols/conn

module AIExposure;

export {
    # Define log streams
    redef enum Log::ID += { 
        DAILY_LOG, 
        CHANGES_LOG, 
        TRENDS_LOG 
    };
    
    # AI service port definitions
    const ai_ports: set[port] = {
        11434/tcp, 7000/tcp,           # Ollama
        50051/tcp,                     # gRPC
        8000/tcp, 8888/tcp,            # vLLM/FastAPI
        7860/tcp, 8501/tcp,            # Gradio/Streamlit
        18789/tcp, 18798/tcp,          # OpenClaw
        28789/tcp, 56767/tcp           # OpenClaw/QClaw
    } &redef;
    
    # State tracking
    global exposure_state: table[string] of count &persist;
    global last_snapshot: table[string] of count;
    global snapshot_history: vector of table[string] of count;
    
    # Daily snapshot record
    type DailyRecord: record {
        ts: time &log;
        date: string &log;
        service_type: string &log;
        exposed_count: count &log;
        change_from_previous: int &log;
        persistence_rate: double &log;
    };
    
    # Change record
    type ChangeRecord: record {
        ts: time &log;
        event_type: string &log;  # "new" or "disappeared"
        service_type: string &log;
        count: count &log;
        affected_hosts: vector of string &log;
    };
    
    # Trend record
    type TrendRecord: record {
        ts: time &log;
        period: string &log;
        service_type: string &log;
        start_count: count &log;
        end_count: count &log;
        change_pct: double &log;
        trend_direction: string &log;
        stability_score: double &log;
    };
}

# Initialize logging streams
event zeek_init() {
    Log::create_stream(DAILY_LOG, [
        $columns=DailyRecord,
        $path="ai_exposure_daily"
    ]);
    
    Log::create_stream(CHANGES_LOG, [
        $columns=ChangeRecord,
        $path="ai_exposure_changes"
    ]);
    
    Log::create_stream(TRENDS_LOG, [
        $columns=TrendRecord,
        $path="ai_exposure_trends"
    ]);
    
    print "AI Exposure Tracker initialized";
    print fmt("Tracking AI ports: %s", ai_ports);
}

# Service type mapping
function get_service_type(p: port): string {
    if ( p == 11434/tcp || p == 7000/tcp )
        return "ollama";
    else if ( p == 50051/tcp )
        return "grpc";
    else if ( p == 8000/tcp || p == 8888/tcp )
        return "vllm";
    else if ( p == 7860/tcp || p == 8501/tcp )
        return "ai_web";
    else if ( p == 18789/tcp || p == 18798/tcp || p == 28789/tcp )
        return "openclaw";
    else if ( p == 56767/tcp )
        return "qclaw";
    else
        return "other";
}

# Track new exposure
function track_new_exposure(host: string, service: string) {
    local key = fmt("%s-%s", host, service);
    
    if ( key !in exposure_state ) {
        exposure_state[key] = 1;
        
        # Log new exposure
        local change = ChangeRecord(
            $ts=current_time(),
            $event_type="new",
            $service_type=service,
            $count=1,
            $affected_hosts=[host]
        );
        Log::write(CHANGES_LOG, change);
    }
}

# Track connection events
event connection_state_remove(c: connection) {
    if ( c$id$resp_p !in ai_ports ) {
        return;
    }
    
    local host = fmt("%s", c$id$resp_h);
    local service = get_service_type(c$id$resp_p);
    local key = fmt("%s-%s", host, service);
    
    track_new_exposure(host, service);
}

# Generate daily snapshot
event timer_event(ts: time) {
    # Aggregate current state by service type
    local current: table[string] of count;
    for ( key in exposure_state ) {
        local parts = split_string(key, /-/);
        if ( |parts| >= 2 ) {
            local host = parts[0];
            local service = parts[1];
            
            if ( service !in current ) {
                current[service] = 0;
            }
            current[service] += 1;
        }
    }
    
    # Store in history
    snapshot_history += current;
    
    # Keep only last 30 snapshots (30 days)
    if ( |snapshot_history| > 30 ) {
        snapshot_history = snapshot_history[|snapshot_history|-30:];
    }
    
    # Calculate and log daily snapshot
    for ( service in current ) {
        local prev_count = 0;
        if ( service in last_snapshot ) {
            prev_count = last_snapshot[service];
        }
        
        local change = (current[service] - prev_count) as int;
        
        # Calculate persistence rate (percentage of IPs seen in previous snapshot)
        local persistence = 0.0;
        if ( prev_count > 0 ) {
            persistence = (current[service] * 1.0 / prev_count) * 100.0;
            if ( persistence > 100.0 ) {
                persistence = 100.0;
            }
        }
        
        local daily = DailyRecord(
            $ts=ts,
            $date=strftime("%Y-%m-%d", ts),
            $service_type=service,
            $exposed_count=current[service],
            $change_from_previous=change,
            $persistence_rate=persistence
        );
        Log::write(DAILY_LOG, daily);
    }
    
    # Update last snapshot
    last_snapshot = current;
    
    print fmt("[%s] Daily snapshot complete", strftime("%Y-%m-%d %H:%M:%S", ts));
}

# Calculate trends
event calculate_trends(ts: time) {
    if ( |snapshot_history| < 2 ) {
        return;
    }
    
    local oldest = snapshot_history[0];
    local newest = snapshot_history[|snapshot_history|-1];
    
    for ( service in newest ) {
        local start_count = 0;
        local end_count = newest[service];
        
        if ( service in oldest ) {
            start_count = oldest[service];
        }
        
        local change_pct = 0.0;
        if ( start_count > 0 ) {
            change_pct = ((end_count - start_count) * 100.0 / start_count);
        }
        
        local direction = "stable";
        if ( change_pct > 5.0 ) {
            direction = "increasing";
        } else if ( change_pct < -5.0 ) {
            direction = "decreasing";
        }
        
        # Calculate stability score (inverse of variance)
        local stability = 1.0;
        if ( |snapshot_history| >= 2 ) {
            local sum = 0.0;
            for ( snap in snapshot_history ) {
                if ( service in snap ) {
                    sum += snap[service];
                }
            }
            local mean = sum / |snapshot_history|;
            
            local variance_sum = 0.0;
            for ( snap in snapshot_history ) {
                if ( service in snap ) {
                    local diff = (snap[service] - mean);
                    variance_sum += diff * diff;
                }
            }
            local variance = variance_sum / |snapshot_history|;
            if ( mean > 0 ) {
                stability = 1.0 - (variance / (mean * mean));
                if ( stability < 0.0 ) {
                    stability = 0.0;
                }
            }
        }
        
        local trend = TrendRecord(
            $ts=ts,
            $period=fmt("last_%d_days", |snapshot_history|),
            $service_type=service,
            $start_count=start_count,
            $end_count=end_count,
            $change_pct=change_pct,
            $trend_direction=direction,
            $stability_score=stability
        );
        Log::write(TRENDS_LOG, trend);
    }
}

# Schedule periodic snapshots (every hour)
event zeek_done() {
    # Schedule daily snapshot every hour
    schedule 1hr { timer_event(get_current_timestamp()) };
    
    # Schedule trend calculation daily
    schedule 1day { calculate_trends(get_current_timestamp()) };
    
    print "AI Exposure Tracker scheduling complete";
}

# =============================================================================
# Summary Report Generation
# =============================================================================

event generate_summary() {
    print "\n========================================";
    print "AI EXPOSURE SUMMARY REPORT";
    print "========================================";
    print fmt("Generated: %s", strftime("%Y-%m-%d %H:%M:%S", current_time()));
    print fmt("Total Tracked IPs: %d", |exposure_state|);
    print "";
    
    # Service breakdown
    local by_service: table[string] of count;
    for ( key in exposure_state ) {
        local parts = split_string(key, /-/);
        if ( |parts| >= 2 ) {
            local service = parts[1];
            if ( service !in by_service ) {
                by_service[service] = 0;
            }
            by_service[service] += 1;
        }
    }
    
    print "Exposure by Service Type:";
    for ( service in by_service ) {
        print fmt("  %s: %d", service, by_service[service]);
    }
    
    print "";
    print "========================================\n";
}

# =============================================================================
# END OF SCRIPT
# =============================================================================
#
# OUTPUT FILES:
#   - ai_exposure_daily.log: Daily exposure snapshots
#   - ai_exposure_changes.log: New/disappeared exposures
#   - ai_exposure_trends.log: Trend analysis
#
# LOG ROTATION:
#   Configure in zeekctl:
#   logdir = /var/log/zeek/ai_exposure
#   logrotationinterval = 1day
#
# ALERT THRESHOLDS:
#   Configure in local.zeek:
#   const alert_thresholds: table[string] of double = {
#       ["ollama"] = 30.0,  # Alert if change > 30%
#       ["grpc"] = 30.0,
#       ["ai_web"] = 50.0,
#   };
#
# PERFORMANCE NOTES:
#   - Persist table to disk for recovery
#   - Archive old snapshots to reduce memory
#   - Consider using SQLite for large-scale deployments
#
# =============================================================================
