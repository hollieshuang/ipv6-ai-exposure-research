# =============================================================================
# ai_banner_extract.zeek - AI Service Banner Extraction Script for Zeek
# Version: 1.0.0
# Date: 2026-07-20
# License: MIT License
# =============================================================================
#
# DESCRIPTION:
# This Zeek script extracts and identifies AI service banners from network
# traffic, supporting Ollama, gRPC, vLLM, and OpenClaw frameworks.
#
# USAGE:
#   zeek -C -b ai_banner_extract.zeek -i eth0
#   zeek -C -b ai_banner_extract.zeek -r capture.pcap
#
# OUTPUT:
#   - ai_banners.log: Extracted AI service banners
#   - ai_services.log: Identified AI services
#   - ai_alerts.log: Security alerts
#
# REQUIREMENTS:
#   - Zeek 4.0+
#   - IPv6 support enabled
#
# =============================================================================

@load base/frameworks/notice
@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/http

module AI;

export {
    # Define log streams
    redef enum Log::ID += { BANNER_LOG, SERVICE_LOG, ALERT_LOG };
    
    # AI service port definitions
    const ai_ports: set[port] = {
        11434/tcp, 7000/tcp,           # Ollama
        50051/tcp,                     # gRPC
        8000/tcp, 8888/tcp,            # vLLM/FastAPI
        7860/tcp, 8501/tcp,            # Gradio/Streamlit
        18789/tcp, 18798/tcp,          # OpenClaw
        28789/tcp, 56767/tcp           # OpenClaw/QClaw
    } &redef;
    
    # Banner record structure
    type BannerRecord: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        service: string &log;
        version: string &optional &log;
        models: vector of string &optional &log;
        banner_text: string &log;
        risk_level: string &log;
    };
    
    # Service record structure
    type ServiceRecord: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        service_type: string &log;
        port: port &log;
        protocol: string &log;
        endpoint: string &optional &log;
        version: string &optional &log;
        models: vector of string &optional &log;
    };
    
    # Alert record structure
    type AlertRecord: record {
        ts: time &log;
        uid: string &log;
        id: conn_id &log;
        alert_type: string &log;
        severity: string &log;
        description: string &log;
        recommendation: string &log;
    };
}

# Log stream definitions
event zeek_init() {
    # Banner extraction log
    Log::create_stream(BANNER_LOG, [
        $columns=BannerRecord,
        $path="ai_banners"
    ]);
    
    # Service identification log
    Log::create_stream(SERVICE_LOG, [
        $columns=ServiceRecord,
        $path="ai_services"
    ]);
    
    # Security alerts log
    Log::create_stream(ALERT_LOG, [
        $columns=AlertRecord,
        $path="ai_alerts"
    ]);
}

# AI service identification function
function identify_ai_service(p: port): string {
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
        return "unknown";
}

# Ollama API parsing
function parse_ollama_banner(data: string): BannerRecord {
    local version: string = "";
    local models: vector of string;
    local risk_level = "LOW";
    
    # Extract version
    if ( /version|Version/ in data ) {
        local v_match = /Ollama version v?([0-9.]+)/;
        if ( v_match in data ) {
            version = v_match$1;
        }
    }
    
    # Extract model list (simplified parsing)
    # In real deployment, use JSON parsing
    if ( /llama|deepseek|qwen|mistral|gemma/ in data ) {
        risk_level = "MEDIUM";
        
        # Note: Full JSON parsing requires JSON Zeek package
        # This is a simplified pattern-based extraction
        if ( /llama3/ in data ) {
            models += "llama3:latest";
        }
        if ( /deepseek-r1/ in data ) {
            models += "deepseek-r1:8b";
        }
        if ( /qwen/ in data ) {
            models += "qwen3:4b";
        }
    }
    
    return BannerRecord($ts=current_time(), $uid="", $id=[]$,
                        $service="ollama", $version=version,
                        $models=models, $banner_text=data,
                        $risk_level=risk_level);
}

# gRPC detection
function detect_grpc_connection(c: connection): bool {
    # Check for HTTP/2 connection preface
    if ( c?$orig && c$orig?$payload && |c$orig$payload| >= 24 ) {
        local preface = sub_bytes(c$orig$payload, 0, 24);
        #PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
        if ( is_prefix(preface, "\\x00\\x00\\x00\\x04PRI * HTTP/2") ) {
            return T;
        }
    }
    return F;
}

# Main connection event handler
event connection_state_remove(c: connection) {
    # Only process AI service ports
    if ( c$id$resp_p !in ai_ports ) {
        return;
    }
    
    local service_type = identify_ai_service(c$id$resp_p);
    local ts = c$start_time;
    local uid = c$uid;
    local id = c$id;
    
    # Log identified AI service
    local service_rec = ServiceRecord(
        $ts=ts,
        $uid=uid,
        $id=id,
        $service_type=service_type,
        $port=c$id$resp_p,
        $protocol="tcp"
    );
    Log::write(SERVICE_LOG, service_rec);
    
    # Generate alerts for high-risk configurations
    if ( service_type == "ollama" ) {
        local alert = AlertRecord(
            $ts=ts,
            $uid=uid,
            $id=id,
            $alert_type="OLLAMA_EXPOSURE",
            $severity="HIGH",
            $description="Ollama service exposed without authentication",
            $recommendation="Enable authentication via OLLAMA_HOST=127.0.0.1 or configure firewall rules"
        );
        Log::write(ALERT_LOG, alert);
    }
    
    if ( service_type == "grpc" && detect_grpc_connection(c) ) {
        # Check for TLS
        if ( !c?$ssl ) {
            local grpc_alert = AlertRecord(
                $ts=ts,
                $uid=uid,
                $id=id,
                $alert_type="GRPC_NO_TLS",
                $severity="HIGH",
                $description="gRPC service exposed without TLS encryption",
                $recommendation="Enable TLS for gRPC services to prevent eavesdropping"
            );
            Log::write(ALERT_LOG, grpc_alert);
        }
    }
}

# HTTP request handler for API endpoints
event http_request(c: connection, method: string, original_URI: string, version: string) {
    if ( c$id$resp_p !in ai_ports ) {
        return;
    }
    
    local uri = original_URI;
    local risk_level = "LOW";
    local alert_type = "";
    local description = "";
    
    # Ollama API endpoints
    if ( /api\/tags/ in uri ) {
        alert_type = "OLLAMA_MODEL_ENUMERATION";
        risk_level = "MEDIUM";
        description = "Attempted to enumerate Ollama models via /api/tags";
    }
    else if ( /api\/generate/ in uri ) {
        alert_type = "OLLAMA_INFERENCE";
        risk_level = "HIGH";
        description = "Inference request to Ollama API";
    }
    else if ( /api\/pull/ in uri ) {
        alert_type = "OLLAMA_MODEL_DOWNLOAD";
        risk_level = "CRITICAL";
        description = "Attempted model download from Ollama";
    }
    else if ( /api\/version/ in uri ) {
        alert_type = "OLLAMA_VERSION_DISCLOSURE";
        risk_level = "LOW";
        description = "Version information disclosure request";
    }
    
    # vLLM API endpoints
    else if ( /v1\/models/ in uri ) {
        alert_type = "VLLM_MODEL_ENUMERATION";
        risk_level = "MEDIUM";
        description = "Attempted to enumerate vLLM models";
    }
    else if ( /v1\/chat\/completions/ in uri ) {
        alert_type = "VLLM_INFERENCE";
        risk_level = "HIGH";
        description = "Inference request to vLLM API";
    }
    
    # Generate alert if suspicious endpoint detected
    if ( alert_type != "" ) {
        local alert = AlertRecord(
            $ts=c$start_time,
            $uid=c$uid,
            $id=c$id,
            $alert_type=alert_type,
            $severity=risk_level,
            $description=description,
            $recommendation="Investigate source IP for unauthorized access attempts"
        );
        Log::write(ALERT_LOG, alert);
    }
}

# Banner extraction from HTTP responses
event http_reply(c: connection, version: string, code: count, reason: string) {
    if ( c$id$resp_p !in ai_ports ) {
        return;
    }
    
    # Extract banner from response body if available
    if ( c?$http && c$http?$status_body ) {
        local body = c$http$status_body;
        
        if ( |body| > 0 ) {
            # Parse banner based on service type
            local service_type = identify_ai_service(c$id$resp_p);
            
            if ( service_type == "ollama" ) {
                local banner = parse_ollama_banner(fmt("%s", body));
                banner$uid = c$uid;
                banner$id = c$id;
                Log::write(BANNER_LOG, banner);
            }
        }
    }
}

# =============================================================================
# END OF SCRIPT
# =============================================================================
#
# OUTPUT FILES:
#   - ai_banners.log: Extracted AI service banners
#   - ai_services.log: Identified AI services
#   - ai_alerts.log: Security alerts
#
# LOG FORMAT:
#   JSON format with the following fields:
#   
#   ai_banners.log:
#   {
#     "ts": "2026-07-20T12:00:00.000Z",
#     "uid": "...",
#     "id.orig_h": "...",
#     "id.orig_p": ...,
#     "id.resp_h": "...",
#     "id.resp_p": ...,
#     "service": "ollama",
#     "version": "0.17.5",
#     "models": ["llama3:latest", "deepseek-r1:8b"],
#     "banner_text": "...",
#     "risk_level": "MEDIUM"
#   }
#
# TROUBLESHOOTING:
#   - If banners are not extracted, ensure HTTP logging is enabled
#   - Check Zeek logs for parsing errors
#   - Adjust body size limits if needed
#
# PERFORMANCE:
#   - This script adds minimal overhead to normal Zeek processing
#   - Banner extraction can be disabled for high-volume networks
#
# =============================================================================
