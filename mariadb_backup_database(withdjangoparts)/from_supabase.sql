-- WARNING: This schema is for context only and is not meant to be run.
-- Table order and constraints may not be valid for execution.

-- eto lang yung kaya ibigay ng supabase.


CREATE TABLE public.candidates (
  id integer NOT NULL DEFAULT nextval('candidates_id_seq'::regclass),
  position_id integer NOT NULL,
  name character varying NOT NULL,
  image character varying,
  campaign_message text,
  department text,
  year_level character varying,
  course character varying,
  skills text,
  platform text,
  goals text,
  sg_years character varying,
  previous_role character varying,
  experience text,
  achievements text,
  slogan text,
  note text,
  edit_locked boolean DEFAULT false,
  CONSTRAINT candidates_pkey PRIMARY KEY (id),
  CONSTRAINT candidates_position_id_fkey FOREIGN KEY (position_id) REFERENCES public.positions(id)
);
CREATE TABLE public.classroom_candidates (
  id integer NOT NULL DEFAULT nextval('classroom_candidates_id_seq'::regclass),
  position_id integer NOT NULL,
  name character varying NOT NULL,
  image character varying,
  campaign_message text,
  year_level character varying,
  course character varying,
  skills text,
  platform text,
  goals text,
  sg_years character varying,
  previous_role character varying,
  experience text,
  achievements text,
  slogan text,
  note text,
  edit_locked boolean DEFAULT false,
  section character varying,
  track character varying,
  CONSTRAINT classroom_candidates_pkey PRIMARY KEY (id),
  CONSTRAINT classroom_candidates_position_id_fkey FOREIGN KEY (position_id) REFERENCES public.classroom_positions(id)
);
CREATE TABLE public.classroom_positions (
  id integer NOT NULL DEFAULT nextval('classroom_positions_id_seq'::regclass),
  name character varying NOT NULL,
  course character varying,
  year_level character varying,
  section character varying,
  track character varying,
  CONSTRAINT classroom_positions_pkey PRIMARY KEY (id)
);
CREATE TABLE public.classroom_settings (
  id integer NOT NULL DEFAULT nextval('classroom_settings_id_seq'::regclass),
  course character varying,
  year_level character varying,
  section character varying,
  track character varying,
  filing_start timestamp with time zone,
  filing_end timestamp with time zone,
  filing_enabled boolean DEFAULT true,
  start_time timestamp with time zone,
  end_time timestamp with time zone,
  CONSTRAINT classroom_settings_pkey PRIMARY KEY (id)
);
CREATE TABLE public.classroom_votes (
  id integer NOT NULL DEFAULT nextval('classroom_votes_id_seq'::regclass),
  student_id character varying NOT NULL,
  position_id integer NOT NULL,
  candidate_id character varying NOT NULL,
  candidate_ref integer,
  course character varying,
  year_level character varying,
  section character varying,
  track character varying,
  created_at timestamp with time zone DEFAULT now(),
  CONSTRAINT classroom_votes_pkey PRIMARY KEY (id)
);
CREATE TABLE public.dashboard_status (
  id integer NOT NULL DEFAULT nextval('dashboard_status_id_seq'::regclass),
  dashboard_name character varying NOT NULL UNIQUE,
  is_active boolean NOT NULL DEFAULT true,
  CONSTRAINT dashboard_status_pkey PRIMARY KEY (id)
);
CREATE TABLE public.global_settings (
  id integer NOT NULL DEFAULT nextval('global_settings_id_seq'::regclass),
  voting_start timestamp with time zone,
  voting_end timestamp with time zone,
  filing_start timestamp with time zone,
  filing_end timestamp with time zone,
  voting_enabled boolean DEFAULT true,
  filing_enabled boolean DEFAULT true,
  CONSTRAINT global_settings_pkey PRIMARY KEY (id)
);
CREATE TABLE public.logs (
  id integer NOT NULL DEFAULT nextval('logs_id_seq'::regclass),
  user_id integer,
  action character varying NOT NULL,
  target text,
  table_name character varying,
  query_type character varying,
  new_data text,
  old_data text,
  timestamp timestamp with time zone DEFAULT now(),
  CONSTRAINT logs_pkey PRIMARY KEY (id),
  CONSTRAINT logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.user(id)
);
CREATE TABLE public.pending_users (
  id integer NOT NULL DEFAULT nextval('pending_users_id_seq'::regclass),
  school_id character varying NOT NULL,
  course character varying,
  email character varying NOT NULL,
  password_plain text NOT NULL,
  first_name character varying,
  last_name character varying,
  phone character varying,
  id_photo_front text,
  id_photo_back text,
  submitted_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
  course_code character varying,
  track character varying,
  department character varying,
  year_level character varying,
  section character varying,
  CONSTRAINT pending_users_pkey PRIMARY KEY (id)
);
CREATE TABLE public.positions (
  id integer NOT NULL DEFAULT nextval('positions_id_seq'::regclass),
  name character varying NOT NULL,
  department character varying NOT NULL,
  course character varying,
  year_level character varying,
  section character varying,
  track character varying,
  CONSTRAINT positions_pkey PRIMARY KEY (id)
);
CREATE TABLE public.receipt_access_logs (
  id integer NOT NULL DEFAULT nextval('receipt_access_logs_id_seq'::regclass),
  school_id character varying NOT NULL,
  viewed_at timestamp without time zone NOT NULL,
  expired_at timestamp without time zone NOT NULL,
  status text DEFAULT 'active'::text CHECK (status = ANY (ARRAY['active'::text, 'expired'::text])),
  CONSTRAINT receipt_access_logs_pkey PRIMARY KEY (id)
);
CREATE TABLE public.settings (
  id integer NOT NULL DEFAULT nextval('settings_id_seq'::regclass),
  department character varying NOT NULL,
  voting_deadline timestamp with time zone,
  start_time timestamp with time zone,
  end_time timestamp with time zone,
  filing_start timestamp with time zone,
  filing_end timestamp with time zone,
  CONSTRAINT settings_pkey PRIMARY KEY (id)
);
CREATE TABLE public.user (
  id integer NOT NULL DEFAULT nextval('user_id_seq'::regclass),
  school_id character varying NOT NULL UNIQUE,
  course character varying NOT NULL,
  email character varying NOT NULL UNIQUE,
  password_hash text NOT NULL,
  first_name character varying NOT NULL,
  last_name character varying NOT NULL,
  phone character varying NOT NULL UNIQUE,
  id_photo_front text NOT NULL,
  id_photo_back text NOT NULL,
  role character varying NOT NULL DEFAULT 'user'::character varying,
  created_at timestamp with time zone DEFAULT now(),
  course_code character varying,
  track character varying,
  year_level character varying,
  department character varying,
  active text DEFAULT 'OFFLINE'::text,
  reset_token text,
  reset_token_expiry text,
  reset_otp text,
  reset_otp_expiry timestamp with time zone,
  section character varying,
  CONSTRAINT user_pkey PRIMARY KEY (id)
);
CREATE TABLE public.votes (
  id integer NOT NULL DEFAULT nextval('votes_id_seq'::regclass),
  student_id character varying,
  position_id integer,
  candidate_id text,
  department character varying,
  candidate_ref integer,
  CONSTRAINT votes_pkey PRIMARY KEY (id),
  CONSTRAINT votes_candidate_ref_fkey FOREIGN KEY (candidate_ref) REFERENCES public.candidates(id),
  CONSTRAINT votes_position_id_fkey FOREIGN KEY (position_id) REFERENCES public.positions(id),
  CONSTRAINT votes_student_id_fkey FOREIGN KEY (student_id) REFERENCES public.user(school_id)
);