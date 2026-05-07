CREATE TABLE users (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(128) NOT NULL UNIQUE,
  display_name VARCHAR(128) NOT NULL DEFAULT '',
  password_hash VARCHAR(255) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'active',
  is_admin BOOLEAN NOT NULL DEFAULT FALSE,
  last_login_at DATETIME NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL
);

CREATE TABLE user_groups (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(128) NOT NULL UNIQUE,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL
);

CREATE TABLE user_group_members (
  group_id BIGINT NOT NULL,
  user_id BIGINT NOT NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (group_id, user_id),
  INDEX idx_user_group_members_user (user_id)
);

CREATE TABLE apps (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(128) NOT NULL,
  domain VARCHAR(255) NOT NULL UNIQUE,
  backend_url VARCHAR(512) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  proxy_timeout_ms INT NOT NULL DEFAULT 30000,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL
);

CREATE TABLE policies (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  app_id BIGINT NOT NULL,
  subject VARCHAR(32) NOT NULL,
  subject_id BIGINT NOT NULL,
  effect VARCHAR(32) NOT NULL DEFAULT 'allow',
  not_before DATETIME NULL,
  not_after DATETIME NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  INDEX idx_policies_app_subject (app_id, subject, subject_id)
);

CREATE TABLE access_logs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT NULL,
  username VARCHAR(128) NULL,
  source_ip VARCHAR(64) NOT NULL,
  domain VARCHAR(255) NOT NULL,
  path VARCHAR(2048) NOT NULL,
  method VARCHAR(16) NOT NULL,
  status_code INT NOT NULL,
  duration_ms BIGINT NOT NULL,
  proxy_result VARCHAR(64) NOT NULL,
  user_agent VARCHAR(1024) NOT NULL DEFAULT '',
  browser VARCHAR(64) NOT NULL DEFAULT '',
  os VARCHAR(64) NOT NULL DEFAULT '',
  created_at DATETIME NOT NULL,
  INDEX idx_access_logs_user_time (user_id, created_at),
  INDEX idx_access_logs_ip_time (source_ip, created_at),
  INDEX idx_access_logs_domain_time (domain, created_at),
  INDEX idx_access_logs_status_time (status_code, created_at)
);

CREATE TABLE login_logs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(128) NOT NULL,
  source_ip VARCHAR(64) NOT NULL,
  result VARCHAR(32) NOT NULL,
  failure_reason VARCHAR(128) NULL,
  created_at DATETIME NOT NULL,
  INDEX idx_login_logs_user_time (username, created_at),
  INDEX idx_login_logs_ip_time (source_ip, created_at)
);

CREATE TABLE admin_logs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  admin_user_id BIGINT NOT NULL,
  admin_username VARCHAR(128) NOT NULL,
  object_type VARCHAR(64) NOT NULL,
  object_id BIGINT NULL,
  action VARCHAR(64) NOT NULL,
  before_summary TEXT NULL,
  after_summary TEXT NULL,
  created_at DATETIME NOT NULL,
  INDEX idx_admin_logs_admin_time (admin_user_id, created_at),
  INDEX idx_admin_logs_object_time (object_type, object_id, created_at)
);

