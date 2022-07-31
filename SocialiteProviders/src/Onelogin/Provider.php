<?php

namespace SocialiteProviders\Onelogin;

use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use SocialiteProviders\Manager\OAuth2\User;

class Provider extends AbstractProvider
{
    /**
     * Unique Provider Identifier.
     */
    const IDENTIFIER = 'ONELOGIN';

    /**
     * {@inheritdoc}
     */
    protected $scopes = ['openid profile'];

    public static function additionalConfigKeys()
    {
        return ['base_url'];
    }

    protected function getBaseUrl()
    {
        return $this->getConfig('base_url');
    }
	
    /**
     * {@inheritdoc}
     */
    protected function getAuthUrl($state)
    {
        return $this->buildAuthUrlFromBase($this->getBaseUrl().'/oidc/2/auth', $state);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenUrl()
    {
		return $this->getBaseUrl().'/oidc/2/token';
    }

    /**
     * {@inheritdoc}
     */
    protected function getUserByToken($token)
    {
        $response = $this->getHttpClient()->get($this->getBaseUrl().'/oidc/2/me', [
            RequestOptions::HEADERS => [
                'Authorization' => 'Bearer '.$token,
            ],
        ]);

        return json_decode((string) $response->getBody(), true);
    }

    /**
     * {@inheritdoc}
     */
    protected function mapUserToObject(array $user)
    {
        return (new User())->setRaw($user)->map([
            'id'       => $user['sub'],
            'nickname' => $user['preferred_username'],
            'name'     => $user['name'],
            'email'    => $user['email']
        ]);
    }

    /**
     * {@inheritdoc}
     */
    protected function getTokenFields($code)
    {
        return array_merge(parent::getTokenFields($code), [
            'grant_type' => 'authorization_code'
        ]);
    }
	
	/**
     * Return logout endpoint with redirect_uri query parameter.
     *
     * @param string|null $redirectUri
     *
     * @return string
     */
    public function getLogoutUrl(?string $redirectUri = null,?string $id_token = null): string
    {
        $logoutUrl = $this->getBaseUrl().'/oidc/2/logout';

        if ($redirectUri === null || $id_token === null) {
            return $logoutUrl;
        }

        return $logoutUrl.'?post_logout_redirect_uri='.urlencode($redirectUri)."&id_token=".$id_token;
    }
}
