# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [unreleased]

## [0.1.7] - 2018-11-02

### Changed
- Added some properties(`email` and `is_verified_adult`) for `User` class

## [0.1.6] - 2018-11-02

### Changed
- `OAuth2Middleware::getUser()` is now able to return nullable value.

## [0.1.5] - 2018-10-18

### Added
- `OAuth2ServiceProviderBundle` for Symfony4

## [0.1.4] - 2018-10-05

### Changed
- `DefaultUserProvider` is now available for not only `*.ridibooks.com` but all account server domains(eg. `*.dev.ridi.io`).

## [0.1.3] - 2018-05-09

### Added
- New `UserProviderInterface` implementation: `DefaultUserProvider` for default action to acquire user information from URL
- New Option: `OAuth2ProviderKeyConstant::USER_INFO_URL` option for provider

### Changed
- Make the 1st param `$state` of `Granter::authorize()` optional

## [0.1.2] - 2018-04-30
### Added
- Introduce new `ridi.oauth2.authorizer` Silex service provider utilized by `Authorizer` class.
- `Authorizer` class for dealing with authorization without Silex context

### Changed
- Parameters of `JwtTokenValidator` are changed.

### Removed
- `ridi.oauth2.token_validator` Silex service provider
- `JwtInfo` class is removed.

## [0.1.1] - 2018-04-26
### Fixed
- Make `JwtTokenValidator::validateToken()` handle nullable access_token properly [#6](https://github.com/ridi/php-oauth2/pull/6)

## [0.1.0] - 2018-04-25
### Added
- Silex Provider [#5](https://github.com/ridi/php-oauth2/pull/5)

## [0.0.2] - 2018-04-09
### Added
- Middlewares for Symfony [#3](https://github.com/ridi/php-oauth2/pull/3)

## [0.0.1] - 2018-03-20
### Added
- Initial release


[unreleased]: https://github.com/ridi/php-oauth2/compare/v0.1.7...HEAD
[0.1.7]: https://github.com/ridi/php-oauth2/compare/v0.1.5...v0.1.7
[0.1.6]: https://github.com/ridi/php-oauth2/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/ridi/php-oauth2/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/ridi/php-oauth2/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/ridi/php-oauth2/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/ridi/php-oauth2/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/ridi/php-oauth2/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/ridi/php-oauth2/compare/v0.0.2...v0.1.0
[0.0.2]: https://github.com/ridi/php-oauth2/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/ridi/php-oauth2/compare/4de01077bd941d3af4c8ed7e42777905db528f48...v0.0.1
