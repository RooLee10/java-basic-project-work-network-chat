CREATE TABLE users (
	user_id serial4 NOT NULL,
	user_name varchar(250) NOT NULL,
	login varchar(250) NOT NULL,
	"password" varchar(250) NOT NULL,
	salt varchar(250) NOT NULL,
	ban_time timestamptz NULL,
	CONSTRAINT users_login_un UNIQUE (login),
	CONSTRAINT users_pkey PRIMARY KEY (user_id),
	CONSTRAINT users_user_name_un UNIQUE (user_name)
);

CREATE TABLE roles (
	role_id int4 DEFAULT nextval('"Roles_role_id_seq"'::regclass) NOT NULL,
	role_name varchar(100) NOT NULL,
	CONSTRAINT roles_pkey PRIMARY KEY (role_id),
	CONSTRAINT roles_un UNIQUE (role_name)
);

CREATE TABLE usertorole (
	user_id int4 NOT NULL,
	role_id int4 NOT NULL,
	CONSTRAINT usertorole_pkey PRIMARY KEY (user_id, role_id)
);


ALTER TABLE public.usertorole ADD CONSTRAINT usertorole_role_id_fk FOREIGN KEY (role_id) REFERENCES roles(role_id);
ALTER TABLE public.usertorole ADD CONSTRAINT usertorole_user_id_fk FOREIGN KEY (user_id) REFERENCES users(user_id);