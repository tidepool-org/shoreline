# Shoreline

Shoreline is the module that manages logins and user accounts.

## 1.3.0
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

# Tidepool Changelog
## HEAD

## v0.15.0

* Add `id` query parameter to `/users` endpoint. Fixes [BACK-145](https://tidepool.atlassian.net/browse/BACK-145)
* Change to go modules. Still vendor dependencies.
* Update to Go 1.12.7
