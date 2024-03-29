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
    application_id uuid,
    organization_id uuid,
    user_id uuid,
    name text NOT NULL,
    status text NOT NULL DEFAULT 'init'::text,
    description text,
    identifier character varying(255),
    provider character varying(255),
    proving_scheme character varying(32) NOT NULL,
    curve character varying(16) NOT NULL,
    vault_id uuid NOT NULL,
    proving_key_id uuid,
    verifying_key_id uuid,
    store_id uuid,
    abi bytea,
    bin bytea
);


ALTER TABLE public.circuits OWNER TO current_user;

--
-- Name: circuits circuits_pkey; Type: CONSTRAINT; Schema: public; Owner: privacy
--

ALTER TABLE ONLY public.circuits
    ADD CONSTRAINT circuits_pkey PRIMARY KEY (id);

--
-- Name: idx_circuits_application_id; Type: INDEX; Schema: public; Owner: privacy
--

CREATE INDEX idx_circuits_application_id ON public.circuits USING btree (application_id);

--
-- Name: idx_circuits_organization_id; Type: INDEX; Schema: public; Owner: privacy
--

CREATE INDEX idx_circuits_organization_id ON public.circuits USING btree (organization_id);

--
-- Name: idx_circuits_user_id; Type: INDEX; Schema: public; Owner: privacy
--

CREATE INDEX idx_circuits_user_id ON public.circuits USING btree (user_id);

--
-- Name: idx_circuits_provider; Type: INDEX; Schema: public; Owner: privacy
--

CREATE INDEX idx_circuits_provider ON public.circuits USING btree (provider);

--
-- Name: idx_circuits_proving_scheme; Type: INDEX; Schema: public; Owner: privacy
--

CREATE INDEX idx_circuits_proving_scheme ON public.circuits USING btree (proving_scheme);

--
-- Name: idx_circuits_curve; Type: INDEX; Schema: public; Owner: privacy
--

CREATE INDEX idx_circuits_curve ON public.circuits USING btree (curve);

--
-- Name: idx_circuits_status; Type: INDEX; Schema: public; Owner: privacy
--

CREATE INDEX idx_circuits_status ON public.circuits USING btree (status);

--
-- Name: stores; Type: TABLE; Schema: public; Owner: privacy
--

CREATE TABLE public.stores (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    created_at timestamp with time zone NOT NULL,
    name text NOT NULL,
    description text,
    curve character varying(16) NOT NULL,
    provider character varying(255) NOT NULL
);


ALTER TABLE public.stores OWNER TO current_user;

--
-- Name: stores stores_pkey; Type: CONSTRAINT; Schema: public; Owner: privacy
--

ALTER TABLE ONLY public.stores
    ADD CONSTRAINT stores_pkey PRIMARY KEY (id);

--
-- Name: idx_stores_provider; Type: INDEX; Schema: public; Owner: privacy
--

CREATE INDEX idx_stores_provider ON public.stores USING btree (provider);

/*
 * Copyright 2017-2022 Provide Technologies Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

--
-- Name: stores; Type: TABLE; Schema: public; Owner: privacy
--

CREATE TABLE public.hashes (
    id SERIAL PRIMARY KEY,
    store_id uuid NOT NULL,
    hash VARCHAR(256) NOT NULL
);


ALTER TABLE public.hashes OWNER TO current_user;

--
-- Name: idx_hashes_store_id; Type: INDEX; Schema: public; Owner: privacy
--

CREATE INDEX idx_hashes_store_id_hash ON public.hashes USING btree (store_id, hash);

--
-- PostgreSQL database dump complete
--
