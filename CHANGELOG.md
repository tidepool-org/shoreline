# Shoreline

Shoreline is the module that manages logins and user accounts.

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

### Fixed
- Allow shoreline to accept a user update payload with un unchanged username or email.


### Changed
- Fix status response of the service. On some cases (MongoDb restart mainly) the status was in error whereas all other entrypoints responded. 

## dblp.0.1.3 - 2019-02-22

### Changed
- Change secrets property from public to private 
- Fix issues with server secrets

## dblp.0.1.2 - 2019-02-22

### Changed
- Modify Go version

## dblp.0.1.1 - 2019-02-20

### Added
- Allow different secrets for multiple servers
- 

## dblp.0.1.0 - 2019-01-22

### Added
- Add support to MongoDb Authentication

## dblp.0.a - 2018-07-03

### Added
- Enable travis CI build 

# Tidepool Changelog
## HEAD

## v0.15.0

* Add `id` query parameter to `/users` endpoint. Fixes [BACK-145](https://tidepool.atlassian.net/browse/BACK-145)
* Change to go modules. Still vendor dependencies.
* Update to Go 1.12.7
