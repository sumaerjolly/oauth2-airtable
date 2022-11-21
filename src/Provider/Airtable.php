<?php

namespace SumaerJolly\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;
use SumaerJolly\OAuth2\Client\Provider\AirtableUser;

class Airtable extends AbstractProvider
{
  const ACCESS_TOKEN_RESOURCE_OWNER_ID = 'id';

  /**
   * Constructs an OAuth 2.0 service provider.
   *
   * @param array $options An array of options to set on this provider.
   *     Options include `clientId`, `clientSecret`, `redirectUri`, and `state`.
   *     Individual providers may introduce more options, as needed.
   * @param array $collaborators An array of collaborators that may be used to
   *     override this provider's default behavior. Collaborators include
   *     `grantFactory`, `requestFactory`, `httpClient`, and `randomFactory`.
   *     Individual providers may introduce more collaborators, as needed.
   */
  public function __construct(array $options = [], array $collaborators = [])
  {
    parent::__construct($options, $collaborators);
  }

  // protected $code_challenge_method = 'S256';
  // protected $n = 43;


  /**
   * Returns authorization parameters based on provided options.
   *
   * @param  array $options
   * @return array Authorization parameters
   */
  // protected function getAuthorizationParameters(array $options)
  // {
  //   // need to add state, code_challenge,code_challenge_method	
  //   $options = parent::getAuthorizationParameters($options);
  //   $options['code_challenge_method	'] = $this->code_challenge_method;
  // }

  public function getAuthorizationParameters(array $options)
  {
    $code_challenge_method = 'S256';
    $n = 43;
    $code_verifier = bin2hex(random_bytes($n));
    $code_challenge = base64_encode(hash('sha256', $code_verifier));

    $params = array_merge(
      parent::getAuthorizationParameters($options),
      array_filter([
        'code_challenge_method' => $code_challenge_method,
        'code_challenge' => $code_challenge,
        'state' => $code_verifier
      ])
    );

    return $params;
  }

  public function getBaseAuthorizationUrl()
  {
    return 'https://airtable.com/oauth2/v1/authorize';
  }

  public function getBaseAccessTokenUrl(array $params)
  {
    return 'https://airtable.com/oauth2/v1/token';
  }

  public function getResourceOwnerDetailsUrl(AccessToken $token)
  {
    return 'https://api.airtable.com/v0/meta/whoami';
  }

  public function getDefaultScopes()
  {
    return [];
  }

  public function checkResponse(ResponseInterface $response, $data)
  {
    if (!empty($data['errors'])) {
      throw new IdentityProviderException($data['errors'], 0, $data);
    }

    return $data;
  }

  protected function createResourceOwner(array $response, AccessToken $token)
  {
    return new AirtableUser($response);
  }
}
