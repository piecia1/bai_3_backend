"UPDATE TableName SET TableField = TableField + 1 WHERE SomeFilterField = @ParameterID"

create table users4(
user4_id int primary key,
name varchar2(255),
password varchar2(511),
last_login date,
last_failed_login date,
failed_attemps_login int,
block_after int,
salt varchar2(511),
last_mask varchar2(255),
token int
);

create table fake_users4(
fake_user4_id int primary key,
name varchar2(255),
last_failed_login date,
failed_attemps_login int,
block_after int,
maska varchar2(255)
);

create table mask(
    mask_id int NOT NULL,
    user4_id int NOT NULL,
    mask_hash varchar2(511),
    field_mask varchar2(255),
    PRIMARY KEY (mask_id),
    FOREIGN KEY (user4_id) REFERENCES users4(user4_id)
);

create sequence user4_id MINVALUE 1 START with 1;
create sequence fake_user4_id MINVALUE 1 START with 1;
create sequence mask_id MINVALUE 1 START with 1;

"""
ALTER TABLE users4 ADD last_mask varchar2(255);
ALTER TABLE mask ADD field_mask varchar2(255);
"""