use ry;

create user rooter identified by 'password';

grant all on ry.* to rooter@'%' identified by 'password' with grant option;

flush privileges;
