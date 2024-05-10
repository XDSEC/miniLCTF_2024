CREATE TABLE users (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(100),
    password VARCHAR(100)
);

INSERT INTO users (id, name, password) VALUES ('1', 'Alice', 'password1');
INSERT INTO users (id, name, password) VALUES ('2', 'Bob', 'password2');
INSERT INTO users (id, name, password) VALUES ('3', 'Charlie', 'password3');

