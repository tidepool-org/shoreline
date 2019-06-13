# Shoreline

Shoreline is the module that manages logins and user accounts.

## [UNRELEASED] - 
### Fixed
- Allow shoreline to accept a user update payload with un unchanged username or email.

## [0.1.4] - 2019-04-17

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