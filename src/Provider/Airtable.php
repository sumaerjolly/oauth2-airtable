<?php

namespace SumaerJolly\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RandomLib\Factory as RandomLibFactory;
use SumaerJolly\OAuth2\Client\Provider\AirtableUser;


/**
 * Represents a Airtable OAuth2 service provider (authorization server).
 *
 * @link http://tools.ietf.org/html/rfc6749#section-1.1 Roles (RFC 6749, §1.1)
 */
class Airtable extends AbstractProvider
{
  use BearerAuthorizationTrait;

  /**
   * In addition to state, store a PKCE verifier that will be used when
   * getting the authorization token.
   *
   * @link https://www.oauth.com/oauth2-servers/pkce/authorization-code-exchange/
   *
   * @var string
   */
  protected string $pkceVerifier;

  /**
   * Get the unhashed PKCE Verifier string for the request.
   *
   * @return string
   */
  public function getPkceVerifier(): string
  {
    if (!isset($this->pkceVerifier)) {
      $this->pkceVerifier = $this->generatePkceVerifier();
    }

    return $this->pkceVerifier;
  }

  /**
   * Returns the base URL for authorizing a client.
   *
   * Eg. https://oauth.service.com/authorize
   *
   * @return string
   */
  public function getBaseAuthorizationUrl(): string
  {
    return 'https://airtable.com/oauth2/v1/authorize';
  }

  protected function getAuthorizationParameters(array $options): array
  {
    if (!isset($options['code_challenge'])) {
      $options['code_challenge'] = $this->generatePkceChallenge();
      $options['code_challenge_method'] = 'S256';
    }

    return parent::getAuthorizationParameters($options);
  }

  /**
   * Returns a prepared request for requesting an access token. Overridden
   * to add the required headers for Airtable
   *
   * @param array $params Query string parameters
   * @return RequestInterface
   */
  protected function getAccessTokenRequest(array $params): RequestInterface
  {
    $request = parent::getAccessTokenRequest($params);

    $token_string = base64_encode($this->clientId . ':' . $this->clientSecret);

    return $request->withHeader('Authorization', "Basic $token_string");
  }

  /**
   * Returns the base URL for requesting an access token.
   *
   * Eg. https://oauth.service.com/token
   *
   * @param array $params
   * @return string
   */
  public function getBaseAccessTokenUrl(array $params): string
  {
    return 'https://airtable.com/oauth2/v1/token';
  }

  /**
   * Returns the URL for requesting the resource owner's details.
   *
   * @param AccessToken $token
   * @return string
   */
  public function getResourceOwnerDetailsUrl(AccessToken $token): string
  {
    return 'https://api.airtable.com/v0/meta/whoami';
  }

  /**
   * Returns the default scopes used by this provider.
   *
   * This should only be the scopes that are required to request the details
   * of the resource owner, rather than all the available scopes.
   *
   * @return array
   */
  protected function getDefaultScopes(): array
  {
    return [];
  }

  /**
   * Checks a provider response for errors.
   *
   * @throws IdentityProviderException
   * @param  ResponseInterface $response
   * @param  array|string $data Parsed response data
   * @return void
   */
  protected function checkResponse(ResponseInterface $response, $data): void
  {
    if ($response->getStatusCode() == 200) {
      return;
    }

    $error = $data['error_description'] ?? '';
    $code = $data['code'] ?? $response->getStatusCode();

    throw new IdentityProviderException($error, $code, $data);
  }

  /**
   * Generates a resource owner object from a successful resource owner
   * details request.
   *
   * @param  array $response
   * @param  AccessToken $token
   * @return AirtableUser
   */
  protected function createResourceOwner(array $response, AccessToken $token): AirtableUser
  {
    return new AirtableUser($response);
  }

  /**
   * Gives a URL-friendly Base64-encoded version of a string
   *
   * @link https://www.oauth.com/oauth2-servers/pkce/authorization-request/
   *
   * @param string $param String to encode
   * @return string
   */
  private function base64Urlencode(string $param): string
  {
    return rtrim(strtr(base64_encode($param), '+/', '-_'), '=');
  }

  /**
   * Create a PKCE verifier string.
   *
   * @link https://www.oauth.com/oauth2-servers/pkce/authorization-request/
   *
   * @return string
   */
  public function generatePkceVerifier(): string
  {
    $generator = (new RandomLibFactory)->getMediumStrengthGenerator();
    return $generator->generateString(
      $generator->generateInt(43, 128), // Length between 43-128 characters
      '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~'
    );
  }

  /**
   * Get the hashed and encoded PKCE challenge string for the request.
   *
   * @param string $passed_verifier Verifier string to use. Defaults to $this->getPkceVerifier().
   * @return string
   */
  public function generatePkceChallenge(string $passed_verifier = null): string
  {
    $verifier = $passed_verifier ?? $this->getPkceVerifier();
    return $this->base64Urlencode(hash('SHA256', $verifier, true));
  }
}
