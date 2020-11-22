--
-- PostgreSQL database dump
--

-- Dumped from database version 10.6
-- Dumped by pg_dump version 10.11 (Ubuntu 10.11-1.pgdg16.04+1)

-- The following portion of the pg_dump output should not run during migrations:
-- SET statement_timeout = 0;
-- SET lock_timeout = 0;
-- SET idle_in_transaction_session_timeout = 0;
-- SET client_encoding = 'UTF8';
-- SET standard_conforming_strings = on;
-- SELECT pg_catalog.set_config('search_path', '', false);
-- SET check_function_bodies = false;
-- SET xmloption = content;
-- SET client_min_messages = warning;
-- SET row_security = off;

-- DO
-- $do$
-- BEGIN
--    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE  rolname = 'privacy') THEN
--       CREATE ROLE privacy WITH SUPERUSER LOGIN PASSWORD 'prvdprivacy';
--    END IF;
-- END
-- $do$;

-- SET ROLE privacy;

--
-- Name: plpgsql; Type: EXTENSION; Schema: -; Owner:
--

CREATE EXTENSION IF NOT EXISTS plpgsql WITH SCHEMA pg_catalog;


--
-- Name: EXTENSION plpgsql; Type: COMMENT; Schema: -; Owner:
--

-- COMMENT ON EXTENSION plpgsql IS 'PL/pgSQL procedural language';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner:
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner:
--

-- COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner:
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner:
--

-- COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


ALTER USER current_user WITH NOSUPERUSER;

SET default_tablespace = '';

SET default_with_oids = false;


--
-- Name: circuits; Type: TABLE; Schema: public; Owner: privacy
--

CREATE TABLE public.circuits (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    name text NOT NULL,
    description text,
    type character varying(32) NOT NULL,
    curve character varying(16) NOT NULL,
    constraint_system character varying(16) NOT NULL
);

ALTER TABLE public.circuits OWNER TO current_user;

--
-- Name: circuits circuits_pkey; Type: CONSTRAINT; Schema: public; Owner: privacy
--

ALTER TABLE ONLY public.circuits
    ADD CONSTRAINT circuits_pkey PRIMARY KEY (id);

--
-- Name: idx_circuits_type; Type: INDEX; Schema: public; Owner: privacy
--

CREATE INDEX idx_circuits_type ON public.circuits USING btree (type);

--
-- Name: idx_circuits_curve; Type: INDEX; Schema: public; Owner: privacy
--

CREATE INDEX idx_circuits_curve ON public.circuits USING btree (curve);

--
-- Name: idx_circuits_constraint_systems; Type: INDEX; Schema: public; Owner: privacy
--

CREATE INDEX idx_circuits_constraint_system ON public.circuits USING btree (constraint_system);

--
-- PostgreSQL database dump complete
--
