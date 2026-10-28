-- CloudPulse Platform database schema (PostgreSQL 16).
-- Applied once by db/init/00-init.sh when the database is first created.
-- The application also creates any missing tables on startup.

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

CREATE TABLE public.cloudpulse_ad_kpi_daily (
    day date NOT NULL,
    kpi character varying(60) NOT NULL,
    value numeric
);

CREATE TABLE public.cloudpulse_ad_snapshots (
    section character varying(40) NOT NULL,
    data jsonb,
    ok boolean,
    error text,
    duration_ms integer,
    collected_at timestamp with time zone,
    attempted_at timestamp with time zone
);

CREATE TABLE public.cloudpulse_ai_chats (
    id integer NOT NULL,
    username character varying(100) NOT NULL,
    title character varying(200),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

CREATE SEQUENCE public.cloudpulse_ai_chats_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.cloudpulse_ai_chats_id_seq OWNED BY public.cloudpulse_ai_chats.id;

CREATE TABLE public.cloudpulse_ai_messages (
    id integer NOT NULL,
    chat_id integer NOT NULL,
    role character varying(20) NOT NULL,
    content text,
    datasets jsonb,
    steps jsonb,
    created_at timestamp with time zone DEFAULT now()
);

CREATE SEQUENCE public.cloudpulse_ai_messages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.cloudpulse_ai_messages_id_seq OWNED BY public.cloudpulse_ai_messages.id;

CREATE TABLE public.cloudpulse_alerts (
    id integer NOT NULL,
    alert_type character varying(50),
    severity character varying(20) DEFAULT 'warning'::character varying NOT NULL,
    server_name character varying(255),
    metric character varying(100),
    metric_name character varying(100),
    value numeric(10,2),
    metric_value numeric(10,2),
    threshold numeric(10,2),
    message text,
    details jsonb,
    status character varying(20) DEFAULT 'open'::character varying,
    jira_ticket_key character varying(50),
    created_at timestamp with time zone DEFAULT now(),
    acknowledged_at timestamp with time zone,
    acknowledged_by character varying(100),
    resolved_at timestamp with time zone
);

CREATE SEQUENCE public.cloudpulse_alerts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.cloudpulse_alerts_id_seq OWNED BY public.cloudpulse_alerts.id;

CREATE TABLE public.cloudpulse_audit_log (
    id integer NOT NULL,
    username character varying(100),
    action character varying(200),
    details jsonb,
    ip_address character varying(50),
    ts timestamp with time zone DEFAULT now()
);

CREATE SEQUENCE public.cloudpulse_audit_log_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.cloudpulse_audit_log_id_seq OWNED BY public.cloudpulse_audit_log.id;

CREATE TABLE public.cloudpulse_capacity_daily (
    id integer NOT NULL,
    server_name character varying(255) NOT NULL,
    report_date date NOT NULL,
    avg_cpu_pct numeric(5,2),
    max_cpu_pct numeric(5,2),
    avg_mem_pct numeric(5,2),
    max_mem_pct numeric(5,2),
    total_mem_gb numeric(10,2),
    used_mem_gb numeric(10,2),
    free_mem_gb numeric(10,2),
    avg_disk_pct numeric(5,2),
    max_disk_pct numeric(5,2),
    total_disk_gb numeric(10,2),
    used_disk_gb numeric(10,2),
    free_disk_gb numeric(10,2),
    disk_details jsonb,
    os_name character varying(255),
    host_ip character varying(50),
    created_at timestamp with time zone DEFAULT now()
);

CREATE SEQUENCE public.cloudpulse_capacity_daily_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.cloudpulse_capacity_daily_id_seq OWNED BY public.cloudpulse_capacity_daily.id;

CREATE TABLE public.cloudpulse_capacity_hourly (
    id integer NOT NULL,
    server_name character varying(255) NOT NULL,
    collected_at timestamp with time zone DEFAULT now() NOT NULL,
    cpu_pct numeric(5,2),
    mem_pct numeric(5,2),
    total_mem_gb numeric(10,2),
    used_mem_gb numeric(10,2),
    free_mem_gb numeric(10,2),
    disk_pct numeric(5,2),
    total_disk_gb numeric(10,2),
    used_disk_gb numeric(10,2),
    free_disk_gb numeric(10,2),
    disk_details jsonb,
    os_name character varying(255),
    host_ip character varying(50)
);

CREATE SEQUENCE public.cloudpulse_capacity_hourly_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.cloudpulse_capacity_hourly_id_seq OWNED BY public.cloudpulse_capacity_hourly.id;

CREATE TABLE public.cloudpulse_jira_tickets (
    id integer NOT NULL,
    ticket_key character varying(50),
    ticket_url character varying(500),
    project_key character varying(50),
    summary text,
    description text,
    subsidiary_id character varying(20),
    subsidiary_name character varying(100),
    sr_type character varying(100),
    priority character varying(30) DEFAULT 'Medium'::character varying,
    effort_hours numeric(6,2),
    resolution_steps text,
    status character varying(50) DEFAULT 'Open'::character varying,
    alert_id integer,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT now(),
    raw_input text,
    llm_response jsonb,
    resolution_note text,
    scheduled_resolve_at timestamp with time zone
);

CREATE SEQUENCE public.cloudpulse_jira_tickets_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.cloudpulse_jira_tickets_id_seq OWNED BY public.cloudpulse_jira_tickets.id;

CREATE TABLE public.cloudpulse_report_history (
    id integer NOT NULL,
    schedule_id integer,
    schedule_name text,
    report_type text,
    status text DEFAULT 'pending'::text,
    generated_at timestamp with time zone DEFAULT now(),
    duration_seconds double precision,
    row_count integer,
    error_message text,
    report_data jsonb,
    filters jsonb,
    email_status text,
    recipients text
);

CREATE SEQUENCE public.cloudpulse_report_history_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.cloudpulse_report_history_id_seq OWNED BY public.cloudpulse_report_history.id;

CREATE TABLE public.cloudpulse_scheduled_reports (
    id integer NOT NULL,
    name text NOT NULL,
    report_type text NOT NULL,
    frequency text NOT NULL,
    day_of_week integer,
    day_of_month integer,
    hour integer DEFAULT 8,
    minute integer DEFAULT 0,
    recipients text DEFAULT ''::text,
    filters jsonb,
    enabled boolean DEFAULT true,
    created_by text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    last_run_at timestamp with time zone,
    next_run_at timestamp with time zone
);

CREATE SEQUENCE public.cloudpulse_scheduled_reports_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.cloudpulse_scheduled_reports_id_seq OWNED BY public.cloudpulse_scheduled_reports.id;

CREATE TABLE public.cloudpulse_server_inventory (
    server_key character varying(255) NOT NULL,
    server_name character varying(255) NOT NULL,
    ip_address character varying(100),
    os_name character varying(255),
    vcpu integer,
    memory_gb numeric(10,2),
    disk_gb numeric(12,2),
    es_namespace character varying(255),
    site character varying(50),
    project character varying(255),
    environment character varying(100),
    application character varying(255),
    owner character varying(255),
    criticality character varying(30),
    notes text,
    monitored boolean DEFAULT true,
    last_seen timestamp with time zone,
    updated_by character varying(100),
    updated_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now()
);

CREATE TABLE public.cloudpulse_settings (
    key character varying(200) NOT NULL,
    value text,
    category character varying(100),
    description text,
    is_secret boolean DEFAULT false,
    updated_at timestamp with time zone DEFAULT now(),
    updated_by character varying(100)
);

CREATE TABLE public.cloudpulse_teams_alerts (
    id integer NOT NULL,
    message_id character varying(255) NOT NULL,
    received_at timestamp with time zone,
    raw_text text,
    sender character varying(255),
    server_name character varying(255),
    metric_type character varying(50),
    ig_data jsonb,
    analysis text,
    severity character varying(20),
    jira_key character varying(50),
    jira_url character varying(500),
    resolved boolean DEFAULT false,
    resolved_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    incident_id integer,
    title text,
    project character varying(255),
    entity text,
    hosts jsonb,
    event_refs jsonb,
    alert_ref character varying(50),
    group_key character varying(500),
    metric_check boolean DEFAULT false,
    ig_host character varying(255),
    resolved_by character varying(30),
    parse_version smallint
);

CREATE SEQUENCE public.cloudpulse_teams_alerts_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.cloudpulse_teams_alerts_id_seq OWNED BY public.cloudpulse_teams_alerts.id;

CREATE TABLE public.cloudpulse_teams_jobs (
    job character varying(50) NOT NULL,
    last_run timestamp with time zone
);

CREATE TABLE public.cloudpulse_teams_seen (
    message_id character varying(255) NOT NULL,
    seen_at timestamp with time zone DEFAULT now()
);

CREATE TABLE public.cloudpulse_users (
    id integer NOT NULL,
    username character varying(100) NOT NULL,
    email character varying(255),
    full_name character varying(255),
    hashed_pw character varying(255),
    is_active boolean DEFAULT true,
    is_admin boolean DEFAULT false,
    entra_id character varying(255),
    created_at timestamp with time zone DEFAULT now(),
    last_login timestamp with time zone
);

CREATE SEQUENCE public.cloudpulse_users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

ALTER SEQUENCE public.cloudpulse_users_id_seq OWNED BY public.cloudpulse_users.id;

ALTER TABLE ONLY public.cloudpulse_ai_chats ALTER COLUMN id SET DEFAULT nextval('public.cloudpulse_ai_chats_id_seq'::regclass);

ALTER TABLE ONLY public.cloudpulse_ai_messages ALTER COLUMN id SET DEFAULT nextval('public.cloudpulse_ai_messages_id_seq'::regclass);

ALTER TABLE ONLY public.cloudpulse_alerts ALTER COLUMN id SET DEFAULT nextval('public.cloudpulse_alerts_id_seq'::regclass);

ALTER TABLE ONLY public.cloudpulse_audit_log ALTER COLUMN id SET DEFAULT nextval('public.cloudpulse_audit_log_id_seq'::regclass);

ALTER TABLE ONLY public.cloudpulse_capacity_daily ALTER COLUMN id SET DEFAULT nextval('public.cloudpulse_capacity_daily_id_seq'::regclass);

ALTER TABLE ONLY public.cloudpulse_capacity_hourly ALTER COLUMN id SET DEFAULT nextval('public.cloudpulse_capacity_hourly_id_seq'::regclass);

ALTER TABLE ONLY public.cloudpulse_jira_tickets ALTER COLUMN id SET DEFAULT nextval('public.cloudpulse_jira_tickets_id_seq'::regclass);

ALTER TABLE ONLY public.cloudpulse_report_history ALTER COLUMN id SET DEFAULT nextval('public.cloudpulse_report_history_id_seq'::regclass);

ALTER TABLE ONLY public.cloudpulse_scheduled_reports ALTER COLUMN id SET DEFAULT nextval('public.cloudpulse_scheduled_reports_id_seq'::regclass);

ALTER TABLE ONLY public.cloudpulse_teams_alerts ALTER COLUMN id SET DEFAULT nextval('public.cloudpulse_teams_alerts_id_seq'::regclass);

ALTER TABLE ONLY public.cloudpulse_users ALTER COLUMN id SET DEFAULT nextval('public.cloudpulse_users_id_seq'::regclass);

ALTER TABLE ONLY public.cloudpulse_ad_kpi_daily
    ADD CONSTRAINT cloudpulse_ad_kpi_daily_pkey PRIMARY KEY (day, kpi);

ALTER TABLE ONLY public.cloudpulse_ad_snapshots
    ADD CONSTRAINT cloudpulse_ad_snapshots_pkey PRIMARY KEY (section);

ALTER TABLE ONLY public.cloudpulse_ai_chats
    ADD CONSTRAINT cloudpulse_ai_chats_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cloudpulse_ai_messages
    ADD CONSTRAINT cloudpulse_ai_messages_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cloudpulse_alerts
    ADD CONSTRAINT cloudpulse_alerts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cloudpulse_audit_log
    ADD CONSTRAINT cloudpulse_audit_log_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cloudpulse_capacity_daily
    ADD CONSTRAINT cloudpulse_capacity_daily_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cloudpulse_capacity_daily
    ADD CONSTRAINT cloudpulse_capacity_daily_server_name_report_date_key UNIQUE (server_name, report_date);

ALTER TABLE ONLY public.cloudpulse_capacity_hourly
    ADD CONSTRAINT cloudpulse_capacity_hourly_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cloudpulse_jira_tickets
    ADD CONSTRAINT cloudpulse_jira_tickets_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cloudpulse_report_history
    ADD CONSTRAINT cloudpulse_report_history_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cloudpulse_scheduled_reports
    ADD CONSTRAINT cloudpulse_scheduled_reports_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cloudpulse_server_inventory
    ADD CONSTRAINT cloudpulse_server_inventory_pkey PRIMARY KEY (server_key);

ALTER TABLE ONLY public.cloudpulse_settings
    ADD CONSTRAINT cloudpulse_settings_pkey PRIMARY KEY (key);

ALTER TABLE ONLY public.cloudpulse_teams_alerts
    ADD CONSTRAINT cloudpulse_teams_alerts_message_id_key UNIQUE (message_id);

ALTER TABLE ONLY public.cloudpulse_teams_alerts
    ADD CONSTRAINT cloudpulse_teams_alerts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cloudpulse_teams_jobs
    ADD CONSTRAINT cloudpulse_teams_jobs_pkey PRIMARY KEY (job);

ALTER TABLE ONLY public.cloudpulse_teams_seen
    ADD CONSTRAINT cloudpulse_teams_seen_pkey PRIMARY KEY (message_id);

ALTER TABLE ONLY public.cloudpulse_users
    ADD CONSTRAINT cloudpulse_users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.cloudpulse_users
    ADD CONSTRAINT cloudpulse_users_username_key UNIQUE (username);

CREATE INDEX idx_ai_chats_user ON public.cloudpulse_ai_chats USING btree (username, updated_at DESC);

CREATE INDEX idx_ai_messages_chat ON public.cloudpulse_ai_messages USING btree (chat_id, id);

CREATE INDEX idx_cap_hourly_server ON public.cloudpulse_capacity_hourly USING btree (server_name);

CREATE INDEX idx_cap_hourly_ts ON public.cloudpulse_capacity_hourly USING btree (collected_at DESC);

CREATE INDEX idx_capacity_daily_cpu ON public.cloudpulse_capacity_daily USING btree (avg_cpu_pct DESC);

CREATE INDEX idx_capacity_daily_date ON public.cloudpulse_capacity_daily USING btree (report_date DESC);

CREATE INDEX idx_capacity_daily_disk ON public.cloudpulse_capacity_daily USING btree (avg_disk_pct DESC);

CREATE INDEX idx_capacity_daily_mem ON public.cloudpulse_capacity_daily USING btree (avg_mem_pct DESC);

CREATE INDEX idx_capacity_daily_server ON public.cloudpulse_capacity_daily USING btree (server_name);

CREATE INDEX idx_inventory_project ON public.cloudpulse_server_inventory USING btree (project);

CREATE INDEX idx_teams_alerts_events ON public.cloudpulse_teams_alerts USING gin (event_refs);

CREATE INDEX idx_teams_alerts_group ON public.cloudpulse_teams_alerts USING btree (group_key, metric_type);

CREATE INDEX idx_teams_alerts_incident ON public.cloudpulse_teams_alerts USING btree (incident_id);

CREATE INDEX idx_teams_alerts_received ON public.cloudpulse_teams_alerts USING btree (received_at DESC);

CREATE INDEX idx_teams_alerts_resolved ON public.cloudpulse_teams_alerts USING btree (resolved);

ALTER TABLE ONLY public.cloudpulse_ai_messages
    ADD CONSTRAINT cloudpulse_ai_messages_chat_id_fkey FOREIGN KEY (chat_id) REFERENCES public.cloudpulse_ai_chats(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.cloudpulse_jira_tickets
    ADD CONSTRAINT cloudpulse_jira_tickets_alert_id_fkey FOREIGN KEY (alert_id) REFERENCES public.cloudpulse_alerts(id);

ALTER TABLE ONLY public.cloudpulse_report_history
    ADD CONSTRAINT cloudpulse_report_history_schedule_id_fkey FOREIGN KEY (schedule_id) REFERENCES public.cloudpulse_scheduled_reports(id);

