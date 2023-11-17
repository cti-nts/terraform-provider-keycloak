package provider

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/imdario/mergo"
	"github.com/mrparkers/terraform-provider-keycloak/keycloak"
	"github.com/mrparkers/terraform-provider-keycloak/keycloak/types"
)

func resourceKeycloakOidcGsisTaxisTestIdentityProvider() *schema.Resource {
	oidcGsisTaxisTestSchema := map[string]*schema.Schema{
		"alias": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "The alias uniquely identifies an identity provider and it is also used to build the redirect uri. In case of GsisTaxisTest this is computed and always GsisTaxisTest",
		},
		"display_name": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: "Not used by this provider, Will be implicitly GsisTaxisTest",
		},
		"provider_id": {
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "gsis-taxis-test",
			Description: "provider id, is always GsisTaxisTest, unless you have a extended custom implementation",
		},
		"client_id": {
			Type:        schema.TypeString,
			Required:    true,
			Description: "Client ID.",
		},
		"client_secret": {
			Type:        schema.TypeString,
			Required:    true,
			Sensitive:   true,
			Description: "Client Secret.",
		},
		"default_scopes": { //defaultScope
			Type:        schema.TypeString,
			Optional:    true,
			Default:     "",
			Description: "The scopes to be sent when asking for authorization. See the documentation for possible values, separator and default value'. Default: 'openid profile email'",
		},
		"accepts_prompt_none_forward_from_client": { // acceptsPromptNoneForwardFromClient
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "This is just used together with Identity Provider Authenticator or when kc_idp_hint points to this identity provider. In case that client sends a request with prompt=none and user is not yet authenticated, the error will not be directly returned to client, but the request with prompt=none will be forwarded to this identity provider.",
		},
		"disable_user_info": { //disableUserInfo
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "Disable usage of User Info service to obtain additional user information?  Default is to use this OIDC service.",
		},
		"hide_on_login_page": {
			Type:        schema.TypeBool,
			Optional:    true,
			Default:     false,
			Description: "Hide On Login Page.",
		},
	}
	oidcResource := resourceKeycloakIdentityProvider()
	oidcResource.Schema = mergeSchemas(oidcResource.Schema, oidcGsisTaxisTestSchema)
	oidcResource.CreateContext = resourceKeycloakIdentityProviderCreate(getOidcGsisTaxisTestIdentityProviderFromData, setOidcGsisTaxisTestIdentityProviderData)
	oidcResource.ReadContext = resourceKeycloakIdentityProviderRead(setOidcGsisTaxisTestIdentityProviderData)
	oidcResource.UpdateContext = resourceKeycloakIdentityProviderUpdate(getOidcGsisTaxisTestIdentityProviderFromData, setOidcGsisTaxisTestIdentityProviderData)
	return oidcResource
}

func getOidcGsisTaxisTestIdentityProviderFromData(data *schema.ResourceData) (*keycloak.IdentityProvider, error) {
	rec, defaultConfig := getIdentityProviderFromData(data)
	rec.ProviderId = data.Get("provider_id").(string)
	rec.Alias = "gsis-taxis-test"

	GsisTaxisTestOidcIdentityProviderConfig := &keycloak.IdentityProviderConfig{
		ClientId:                    data.Get("client_id").(string),
		ClientSecret:                data.Get("client_secret").(string),
		HideOnLoginPage:             types.KeycloakBoolQuoted(data.Get("hide_on_login_page").(bool)),
		DefaultScope:                data.Get("default_scopes").(string),
		AcceptsPromptNoneForwFrmClt: types.KeycloakBoolQuoted(data.Get("accepts_prompt_none_forward_from_client").(bool)),
		UseJwksUrl:                  true,
		DisableUserInfo:             types.KeycloakBoolQuoted(data.Get("disable_user_info").(bool)),
	}

	if err := mergo.Merge(GsisTaxisTestOidcIdentityProviderConfig, defaultConfig); err != nil {
		return nil, err
	}

	rec.Config = GsisTaxisTestOidcIdentityProviderConfig

	return rec, nil
}

func setOidcGsisTaxisTestIdentityProviderData(data *schema.ResourceData, identityProvider *keycloak.IdentityProvider) error {
	setIdentityProviderData(data, identityProvider)
	data.Set("provider_id", identityProvider.ProviderId)
	data.Set("client_id", identityProvider.Config.ClientId)
	data.Set("hide_on_login_page", identityProvider.Config.HideOnLoginPage)
	data.Set("default_scopes", identityProvider.Config.DefaultScope)
	data.Set("accepts_prompt_none_forward_from_client", identityProvider.Config.AcceptsPromptNoneForwFrmClt)
	data.Set("disable_user_info", identityProvider.Config.DisableUserInfo)
	return nil
}
