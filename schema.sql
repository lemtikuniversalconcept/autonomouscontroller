CREATE TABLE autonomous_devices (
    id VARCHAR(100) PRIMARY KEY,
    org_id UUID NOT NULL,
    building_id VARCHAR(100),
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    manufacturer VARCHAR(255),
    model VARCHAR(255),
    lat DECIMAL(10,8),
    lng DECIMAL(11,8),
    floor INTEGER,
    zone VARCHAR(100),
    area VARCHAR(255),
    connection_type VARCHAR(50) NOT NULL,
    connection_config JSONB NOT NULL,
    supported_actions JSONB DEFAULT '[]',
    status VARCHAR(50) DEFAULT 'online',
    last_seen TIMESTAMPTZ,
    last_command_at TIMESTAMPTZ,
    last_command_result VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE autonomous_actions_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id VARCHAR(100) NOT NULL,
    org_id UUID NOT NULL,
    incident_id VARCHAR(100),
    action_key VARCHAR(100) NOT NULL,
    parameters JSONB DEFAULT '{}',
    requested_by VARCHAR(100),
    requested_from_ip VARCHAR(100),
    approved_by VARCHAR(100),
    approval_level VARCHAR(50),
    approval_timestamp TIMESTAMPTZ,
    executed_at TIMESTAMPTZ,
    execution_result VARCHAR(50),
    adapter_used VARCHAR(50),
    response_data JSONB,
    error_message TEXT,
    auto_revert_scheduled_at TIMESTAMPTZ,
    reverted_at TIMESTAMPTZ,
    revert_result VARCHAR(50),
    log_level VARCHAR(50),
    life_safety_risk BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE active_overrides (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id VARCHAR(100) NOT NULL,
    org_id UUID NOT NULL,
    incident_id VARCHAR(100),
    action_key VARCHAR(100) NOT NULL,
    action_log_id UUID REFERENCES autonomous_actions_log(id),
    status VARCHAR(50) DEFAULT 'active',
    started_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revert_action VARCHAR(100),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE hardware_bridges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    location VARCHAR(255),
    gateway_key VARCHAR(255) UNIQUE NOT NULL,
    status VARCHAR(50) DEFAULT 'offline',
    last_connected TIMESTAMPTZ,
    firmware_version VARCHAR(50),
    ip_address VARCHAR(50),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
