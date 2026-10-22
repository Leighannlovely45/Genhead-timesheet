-- ─────────────────────────────────────────────────────────────────────────────
-- Genhead Timesheet — Project Management Migration
-- Run once on the Stagging (and production) database
-- ─────────────────────────────────────────────────────────────────────────────

-- Projects: one per client engagement or internal initiative
CREATE TABLE IF NOT EXISTS projects (
    id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name          VARCHAR(255)  NOT NULL,
    client_id     INT UNSIGNED  NULL,           -- FK to clients.id (nullable for internal projects)
    client_name   VARCHAR(255)  NULL,           -- denormalized for display speed
    status        ENUM('active','on_hold','completed','archived') NOT NULL DEFAULT 'active',
    billing_type  ENUM('billable','nonbillable','marketing')      NOT NULL DEFAULT 'billable',
    due_date      DATE          NULL,
    description   TEXT          NULL,
    created_by    INT UNSIGNED  NOT NULL,       -- users.id
    created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status     (status),
    INDEX idx_client     (client_id),
    INDEX idx_created_by (created_by)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tasks: belong to a project, assigned to a user
CREATE TABLE IF NOT EXISTS tasks (
    id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    project_id    INT UNSIGNED  NOT NULL,
    title         VARCHAR(500)  NOT NULL,
    description   TEXT          NULL,
    assigned_to   INT UNSIGNED  NULL,           -- users.id
    assigned_name VARCHAR(255)  NULL,           -- denormalized
    priority      ENUM('low','medium','high')   NOT NULL DEFAULT 'medium',
    stage         ENUM('backlog','todo','inprogress','inreview','done') NOT NULL DEFAULT 'backlog',
    due_date      DATE          NULL,
    billing_type  ENUM('billable','nonbillable','marketing') NULL, -- inherits from project if null
    created_by    INT UNSIGNED  NOT NULL,
    created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_project   (project_id),
    INDEX idx_assigned  (assigned_to),
    INDEX idx_stage     (stage),
    INDEX idx_created   (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Task comments: activity log + team chat per task
CREATE TABLE IF NOT EXISTS task_comments (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    task_id     INT UNSIGNED  NOT NULL,
    user_id     INT UNSIGNED  NOT NULL,
    user_name   VARCHAR(255)  NOT NULL,
    comment     TEXT          NOT NULL,
    is_activity TINYINT(1)    NOT NULL DEFAULT 0,  -- 1 = system activity log (stage move, assign), 0 = human comment
    created_at  DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_task    (task_id),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
