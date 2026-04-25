CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS admins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT UNIQUE NOT NULL,
    phone_number TEXT,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    time_remaining_seconds INTEGER NOT NULL DEFAULT 0 CHECK (time_remaining_seconds >= 0),
    valid_until TIMESTAMPTZ,
    is_unlimited BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    type TEXT NOT NULL,
    amount_seconds INTEGER NOT NULL DEFAULT 0,
    amount_money NUMERIC(12,2),
    reference TEXT,
    note TEXT,
    created_by UUID REFERENCES admins(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS nas_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    nas_ip INET NOT NULL,
    shortname TEXT UNIQUE NOT NULL,
    secret TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'other',
    status TEXT NOT NULL DEFAULT 'active',
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS radius_auth_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT,
    nas_ip INET,
    nas_identifier TEXT,
    calling_station_id TEXT,
    result TEXT NOT NULL,
    reply_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    username TEXT NOT NULL,
    nas_ip INET,
    nas_identifier TEXT,
    calling_station_id TEXT,
    framed_ip_address INET,
    acct_session_id TEXT,
    start_time TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_update_time TIMESTAMPTZ NOT NULL DEFAULT now(),
    stop_time TIMESTAMPTZ,
    input_octets BIGINT NOT NULL DEFAULT 0,
    output_octets BIGINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    UNIQUE (username, acct_session_id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(username, stop_time, last_update_time);
CREATE INDEX IF NOT EXISTS idx_radius_auth_logs_created_at ON radius_auth_logs(created_at DESC);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_admin_id UUID REFERENCES admins(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS radcheck (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op CHAR(2) NOT NULL DEFAULT '==',
    value VARCHAR(253) NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS radreply (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op CHAR(2) NOT NULL DEFAULT '=',
    value VARCHAR(253) NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS radacct (
    radacctid BIGSERIAL PRIMARY KEY,
    acctsessionid VARCHAR(64) NOT NULL DEFAULT '',
    acctuniqueid VARCHAR(32) NOT NULL DEFAULT '',
    username VARCHAR(64) NOT NULL DEFAULT '',
    groupname VARCHAR(64) NOT NULL DEFAULT '',
    realm VARCHAR(64) DEFAULT '',
    nasipaddress INET NOT NULL,
    nasportid VARCHAR(32),
    nasporttype VARCHAR(32),
    acctstarttime TIMESTAMPTZ,
    acctupdatetime TIMESTAMPTZ,
    acctstoptime TIMESTAMPTZ,
    acctinterval BIGINT,
    acctsessiontime BIGINT,
    acctauthentic VARCHAR(32),
    connectinfo_start VARCHAR(50),
    connectinfo_stop VARCHAR(50),
    acctinputoctets BIGINT,
    acctoutputoctets BIGINT,
    calledstationid VARCHAR(50),
    callingstationid VARCHAR(50),
    acctterminatecause VARCHAR(32),
    servicetype VARCHAR(32),
    framedprotocol VARCHAR(32),
    framedipaddress INET
);

CREATE TABLE IF NOT EXISTS radusergroup (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    groupname VARCHAR(64) NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS radgroupcheck (
    id SERIAL PRIMARY KEY,
    groupname VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op CHAR(2) NOT NULL DEFAULT '==',
    value VARCHAR(253) NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS radgroupreply (
    id SERIAL PRIMARY KEY,
    groupname VARCHAR(64) NOT NULL DEFAULT '',
    attribute VARCHAR(64) NOT NULL DEFAULT '',
    op CHAR(2) NOT NULL DEFAULT '=',
    value VARCHAR(253) NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS nas (
    id SERIAL PRIMARY KEY,
    nasname VARCHAR(128) NOT NULL,
    shortname VARCHAR(32) NOT NULL,
    type VARCHAR(30) DEFAULT 'other',
    ports INTEGER,
    secret VARCHAR(60) NOT NULL,
    server VARCHAR(64),
    community VARCHAR(50),
    description VARCHAR(200)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_radcheck_username_attribute ON radcheck(username, attribute);
CREATE UNIQUE INDEX IF NOT EXISTS idx_nas_shortname ON nas(shortname);
