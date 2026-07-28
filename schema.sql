-- DDL Schema representing the same MongoDB structures in standard SQL (PostgreSQL compatible)

-- Table for quizzes
CREATE TABLE IF NOT EXISTS quizzes (
    id VARCHAR(36) PRIMARY KEY, -- Stores UUID
    query TEXT NOT NULL,
    question_mode VARCHAR(50),
    is_coding BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Table for questions
CREATE TABLE IF NOT EXISTS questions (
    id SERIAL PRIMARY KEY,
    quiz_id VARCHAR(36) REFERENCES quizzes(id) ON DELETE CASCADE,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    code TEXT,
    code_lang VARCHAR(50) DEFAULT 'python'
);

-- Table for choices (options for each question)
CREATE TABLE IF NOT EXISTS choices (
    id SERIAL PRIMARY KEY,
    question_id INTEGER REFERENCES questions(id) ON DELETE CASCADE,
    choice_text TEXT NOT NULL
);

-- Table for quiz results
CREATE TABLE IF NOT EXISTS results (
    quiz_id VARCHAR(36) PRIMARY KEY REFERENCES quizzes(id) ON DELETE CASCADE,
    score INTEGER NOT NULL,
    total INTEGER NOT NULL,
    percentage INTEGER NOT NULL,
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Table for user answers (matching Mongoose Map/nested structure)
CREATE TABLE IF NOT EXISTS user_answers (
    id SERIAL PRIMARY KEY,
    quiz_id VARCHAR(36) REFERENCES quizzes(id) ON DELETE CASCADE,
    question_index INTEGER NOT NULL,
    chosen_answer TEXT NOT NULL,
    UNIQUE(quiz_id, question_index)
);

-- Equivalent SQL Queries for backend endpoints:

-- 1. GET /api/history (Fetch all saved quizzes with questions and results)
-- SELECT q.*, r.score, r.total, r.percentage, r.submitted_at 
-- FROM quizzes q 
-- LEFT JOIN results r ON q.id = r.quiz_id
-- ORDER BY q.created_at DESC;

-- 2. POST /api/history (Insert a new quiz)
-- INSERT INTO quizzes (id, query, question_mode, is_coding, created_at)
-- VALUES ($1, $2, $3, $4, $5);

-- 3. PUT /api/history/:id (Update the results of a quiz)
-- INSERT INTO results (quiz_id, score, total, percentage, submitted_at)
-- VALUES ($1, $2, $3, $4, $5)
-- ON CONFLICT (quiz_id) DO UPDATE 
-- SET score = EXCLUDED.score, total = EXCLUDED.total, percentage = EXCLUDED.percentage, submitted_at = EXCLUDED.submitted_at;

-- 4. DELETE /api/history/:id (Delete a quiz)
-- DELETE FROM quizzes WHERE id = $1;
