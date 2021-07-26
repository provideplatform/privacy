CREATE TABLE trees (
    id SERIAL PRIMARY KEY,
    store_id uuid NOT NULL,
    nodes json NOT NULL,
    values json NOT NULL,
    root text NOT NULL
);

CREATE INDEX idx_trees_store_id ON trees USING btree (store_id);
