# Flask Api

## Register
http://127.0.0.1:4000/register

This endpoint using validator. Cant accept exist username or email. If all requirements match, server will respond with data:
#### Data Field:
username
password
email
name
submit_ref


#### Data Response:
username
id
email
name
ref_code

## Login
http://127.0.0.1:4000/login

#### Data Field:
username
password

#### Data Response:
username
id
email
name
ref_code
token

## Edit User
http://127.0.0.1:4000/edit

This endpoint need token in header. Username and email must be unique with data in database or it will response with erorr.

#### Data Field:
username
name
email

#### Data Response:
username
name
email

## Referral
http://127.0.0.1:4000/referral

This endpoint need token in header. This will matching referral code with current user in token. if current user enter their referral code, the respon will be match and vice versa.

#### Data Field:
ref_code

#### Data Response:
match or not match

## Search User
http://127.0.0.1:4000/search

This end point will search username with wildcard feature

#### Data Field:
search

#### Data Response:
email
name
username

## Hero
http://127.0.0.1:4000/search

This end point will search hero name with matching keyword. Its using wildcard feature and randomly pick hero name if found more than 1 hero name.

#### Data Field:
input

#### Data Response:
hero data with matching keyword