# Shoreline

Shoreline is the module that manages user accounts and authentication.

## UNRELEASED 
### Added
- New role "admin" processed in our auth middleware

### Engineering
- Simplify client lib: we do not want to force client services to use server tokens.

## 1.9.1 - 2022-03-02
### Added
- YLP-1310 Unbrick handset created with invalid email address

## 1.9.0 - 2022-02-17
### Engineering 
- Build multi-architecture docker images
### Added
- YLP-1212: Add required routes in shoreline to integrate with the French health platform (cps) using oidc

## 1.8.7 - 2022-01-10 
### Engineering 
- YLP-1166 enhance logging

## 1.8.6 - 2022-01-06
### Fix
- YLP-1162: Do Not sanitize passwords during user creation or update

## 1.8.5 - 2021-12-27
### Added
- YLP-1132 Implement GET users not authenticated in shoreline
- YLP-1134 Add DELETE user in shoreline client

## 1.8.4 - 2021-12-15
### Engineering
- YLP-957 Migrate shoreline to logrus

## 1.8.3  - 2021-11-15
### Fixed
- YLP-1104 Shoreline should not create an account without any role

## 1.8.2 - 2021-10-15
### Changed
- YLP-1065: Automatically add the role "patient" for login requests coming from private api.
- YLP-1057: Allow usage of all characters in passwords, including unicode and whitespace.

## 1.8.1 - 2021-09-28
### Fixed
- YLP-1026: Shoreline cannot start with 200 concurrent users

## 1.8.0 - 2021-09-15
### Changed
- YLP-943: Add basic checks on user email address
- YLP-937: Split configuration of user and server token duration
### Engineering
- YLP-924: Upgrade to go-common v1

## 1.7.0 - 2021-08-06
### Changed
- YLP-911: put in place metrics in shoreline
- YLP-919 Yourloops do not encode correctly passwords with special characters

## 1.6.1 - 2021-05-14
### Changed
- YLP-586: Remove mailchimp and marketo integration

## 1.6.0 - 2021-05-12
### Changed
- YLP-713 Update password: hcp/caregivers must give current password

## 1.5.2 - 2021-05-10
### Fixed
- YLP-702: tokens do not contain relevant role

## 1.5.1 - 2021-05-03
### Fixed
- Correct client mock so it returns the correct role

## 1.5.0 - 2021-04-13
### Changed
- YLP-549: Authorize caregivers to change their role to "hcp"

## 1.4.0 - 2021-03-30
### Changed
- YLP-674: Correct the value of zendesk organization in 3rd party token
### Fixed
- YLP-587 Auth clients should check the Shoreline token with email verified

## 1.3.1 - 2021-03-30
### Engineering
- Move light (jwt) authentication client from crew
- Move full shoreline client from go-common 
- Travis to Jenkins pipeline

## 1.3.0 - 2021-03-30
### Added
- YLP-505 Add patient, hcp and caregiver roles to our user token (used for teams permissions)

### Changed
- YLP-446 Upgrade go-common to 0.6.2 version
- YLP-475 Remove "Custodian" authorization in shoreline

## 1.2.0 - 2020-12-22
### Added
- YLP-339 New route to provide JWT tokens for external services

## 1.1.2 - 2020-10-29
### Engineering
- YLP-243 Review openapi generation so we can serve it through a website
- Update to Go 1.15

## 1.1.1 - 2020-09-25
### Fixed
- Fix S3 deployment

## 1.1.0 - 2020-07-29
### Changed
- PT-1439 Shoreline should be able to start without MongoDb
### Engineering Use
- Removing unused oAuth2 Routes

## 1.0.1 - 2020-07-29
### Engineering Use
- Fix Soup document name: remove dblp from tag

## 1.0.0 - 2020-07-28
### Changed
- PT-1284 Integrate Tidepool master for shoreline
- PT-1389 Generate Soup document from go modules

## 0.6.0 - 2020-04-09
### Changed
- PT-1200 Remove highwater from shoreline (was not used, only declared)
- PT-1247 Allow by Configuration the parallel logins of same account

## 0.5.2 - 2020-03-20
### Fixed
- Fix changelog

## 0.5.1 - 2020-03-18
### Fixed
- PT-1187 Login limiter crashes on simultaneous login

## 0.5.0 - 2020-03-04
### Added
- PT-1026 Implement max login attempt on a user account
### Engineering Use
- PT-1048 Open API documentation

## 0.4.0 - 2019-10-28
### Added
- PT-732 Display the application version number on the status endpoint (/status).

## 0.3.0 - 2019-10-14
### Added
- PT-581 Integration of Tidepool v0.15.0 changes

## 0.2.0 - 2019-07-30
### Added
- Integration from Tidepool latest changes

### Changed
- Update to MongoDb 3.6 drivers in order to use replica set connections
- Fix status response of the service. On some cases (MongoDb restart mainly) the status was in error whereas all other entrypoints responded. 

### Fixed
- Allow shoreline to accept a user update payload with un unchanged username or email.

## 0.1.3 - 2019-02-22

### Changed
- Change secrets property from public to private 
- Fix issues with server secrets

## 0.1.2 - 2019-02-22

### Changed
- Modify Go version

## 0.1.1 - 2019-02-20

### Added
- Allow different secrets for multiple servers
- 

## 0.1.0 - 2019-01-22

### Added
- Add support to MongoDb Authentication
- Enable travis CI build 

