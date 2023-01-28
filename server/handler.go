package server

import (
	"context"
	"net/http"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/josephGuo/oauth2"
	"github.com/josephGuo/oauth2/errors"
)

type (
	// ClientInfoHandler get client info from request
	ClientInfoHandler func(rctx *app.RequestContext) (clientID, clientSecret string, err error)

	// ClientAuthorizedHandler check the client allows to use this authorization grant type
	ClientAuthorizedHandler func(clientID string, grant oauth2.GrantType) (allowed bool, err error)

	// ClientScopeHandler check the client allows to use scope
	ClientScopeHandler func(tgr *oauth2.TokenGenerateRequest) (allowed bool, err error)

	// UserAuthorizationHandler get user id from request authorization
	UserAuthorizationHandler func(c context.Context, rctx *app.RequestContext) (userID string, err error)

	// PasswordAuthorizationHandler get user id from username and password
	PasswordAuthorizationHandler func(ctx context.Context, clientID, username, password string) (userID string, err error)

	// RefreshingScopeHandler check the scope of the refreshing token
	RefreshingScopeHandler func(tgr *oauth2.TokenGenerateRequest, oldScope string) (allowed bool, err error)

	// RefreshingValidationHandler check if refresh_token is still valid. eg no revocation or other
	RefreshingValidationHandler func(ti oauth2.TokenInfo) (allowed bool, err error)

	// ResponseErrorHandler response error handing
	ResponseErrorHandler func(re *errors.Response)

	// InternalErrorHandler internal error handing
	InternalErrorHandler func(err error) (re *errors.Response)

	// PreRedirectErrorHandler is used to override "redirect-on-error" behavior
	PreRedirectErrorHandler func(rctx *app.RequestContext, req *AuthorizeRequest, err error) error

	// AuthorizeScopeHandler set the authorized scope
	AuthorizeScopeHandler func(c context.Context, rctx *app.RequestContext) (scope string, err error)

	// AccessTokenExpHandler set expiration date for the access token
	AccessTokenExpHandler func(c context.Context, rctx *app.RequestContext) (exp time.Duration, err error)

	// ExtensionFieldsHandler in response to the access token with the extension of the field
	ExtensionFieldsHandler func(ti oauth2.TokenInfo) (fieldsValue map[string]interface{})

	// ResponseTokenHandler response token handing
	ResponseTokenHandler func(rctx *app.RequestContext, data map[string]interface{}, header http.Header, statusCode ...int) error
)

// ClientFormHandler get client data from form
func ClientFormHandler(rctx *app.RequestContext) (string, string, error) {
	//ctx.Request.URI().QueryArgs()+ctx.Request.PostArgs()
	clientID := oauth2.B2s(rctx.FormValue("client_id"))
	if clientID == "" {
		return "", "", errors.ErrInvalidClient
	}
	clientSecret := oauth2.B2s(rctx.FormValue("client_secret"))
	return clientID, clientSecret, nil
}

// ClientBasicHandler get client data from basic authorization
func ClientBasicHandler(rctx *app.RequestContext) (string, string, error) {
	username, password, ok := rctx.Request.BasicAuth()
	if !ok {
		return "", "", errors.ErrInvalidClient
	}
	return username, password, nil
}
