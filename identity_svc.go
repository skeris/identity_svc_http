package identity_svc_http

import (
	"context"
	"github.com/themakers/identity/cookie"
	"github.com/themakers/identity/identity"
	"net/http"
	"encoding/json"
	"reflect"
)

// TODO: Should it handle 'app passwords' concept?
// TODO: Support forced verifiers order? (to prevent paid resources overuse)
// TODO: SignIn from SignUp mode if user already exists

const (
	SessionTokenName = "session_token"
	UserName         = "user"
)

type IdentitySvc struct {
	cookieCtxKey string
	mgr          *identity.Manager
}

func New(backend identity.Backend, cookieCtxKey string, identities []identity.Identity, verifiers []identity.Verifier) (*IdentitySvc, error) {
	is := &IdentitySvc{
		cookieCtxKey: cookieCtxKey,
	}

	if mgr, err := identity.New(
		backend,
		identities,
		verifiers,
	); err != nil {
		return nil, err
	} else {
		is.mgr = mgr
	}

	return is, nil
}

func (is *IdentitySvc) Register() (public, private *http.ServeMux) {
	public = http.NewServeMux()
	public.HandleFunc("/ListSupportedIdentitiesAndVerifiers", is.universalHandler(is.listSupportedIdentitiesAndVerifiers))
	public.HandleFunc("/CheckStatus", is.universalHandler(is.checkStatus))
	public.HandleFunc("/StartSignIn", is.universalHandler(is.startSignIn))
	public.HandleFunc("/StartSignUp", is.universalHandler(is.startSignUp))
	public.HandleFunc("/StartAttach", is.universalHandler(is.startAttach))
	public.HandleFunc("/CancelAuthentication", is.universalHandler(is.cancelAuthentication))
	public.HandleFunc("/ListMyIdentitiesAndVerifiers", is.universalHandler(is.listMyIdentitiesAndVerifiers))
	public.HandleFunc("/Start", is.universalHandler(is.start))
	public.HandleFunc("/Verify", is.universalHandler(is.verify))
	public.HandleFunc("/Logout", is.universalHandler(is.logout))
	public.HandleFunc("/UserMerge", is.universalHandler(is.userMerge))

	private = http.NewServeMux()
	private.HandleFunc("/LoginAs", is.universalHandler(is.loginAs))

	return
}

func (is *IdentitySvc) universalHandler(f interface{}) http.HandlerFunc {
	fRV := reflect.ValueOf(f)
	fRT := fRV.Type()

	var argRT reflect.Type
	var argTypeRV reflect.Value
	var argExist bool

	if fRT.NumIn() > 1 {
		argExist = true
		argRT = fRT.In(1)
		argTypeRV = reflect.New(argRT)
	}

	return func(w http.ResponseWriter, q *http.Request) {
		q.Header.Set("Content-Type", "application/json")

		var fResultRV []reflect.Value

		if argExist {
			arg := argTypeRV.Interface()
			if err := json.NewDecoder(q.Body).Decode(&arg); err != nil {
				resp := ErrorResp{
					Text: err.Error(),
				}
				w.WriteHeader(http.StatusInternalServerError)
				if err := json.NewEncoder(w).Encode(resp); err != nil {
					panic(err)
				}
			} else {
				fResultRV = fRV.Call([]reflect.Value{reflect.ValueOf(q.Context()), reflect.ValueOf(arg)})
			}
		} else {
			fResultRV = fRV.Call([]reflect.Value{reflect.ValueOf(q.Context())})
		}

		w.WriteHeader(fResultRV[1].Interface().(int))
		if err := json.NewEncoder(w).Encode(fResultRV[0].Interface()); err != nil {
			panic(err)
		}
	}
}

////////////////////////////////////////////////////////////////
//// Helpers
////

func (is *IdentitySvc) sessionObtain(ctx context.Context) *identity.Session {
	//log.Println("qwertyuiop", ctx.Value(is.cookieCtxKey).(cookie.Cookie).GetSessionID())
	return is.mgr.Session(ctx.Value(is.cookieCtxKey).(cookie.Cookie))
}

////////////////////////////////////////////////////////////////
//// PublicIdentityService
////

func (is *IdentitySvc) status(ctx context.Context, sess *identity.Session) (*Status, error) {
	if status, err := sess.CheckStatus(ctx); err != nil {
		return &Status{}, err
	} else {
		return convertStatus(status), nil
	}
}

func (is *IdentitySvc) start(ctx context.Context, requestData StartReq) (interface{}, int) {
	sess := is.sessionObtain(ctx)

	for k, v := range requestData.Values {
		ctx = context.WithValue(ctx, k, v)
	}

	directions, err := sess.Start(ctx, requestData.VerifierName, requestData.Args, requestData.IdentityName, requestData.Identity)
	if err != nil {
		return ErrorResp{
			Text: err.Error(),
		}, http.StatusInternalServerError
	}

	return StartResp{
		Directions: directions,
	}, http.StatusOK
}

func (is *IdentitySvc) listSupportedIdentitiesAndVerifiers(ctx context.Context) (interface{}, int) {
	sess := is.sessionObtain(ctx)
	resp := VerifierDetailsResp{}

	idns, vers, err := sess.ListSupportedIdentitiesAndVerifiers()
	if err != nil {
		return ErrorResp{
			Text: err.Error(),
		}, http.StatusInternalServerError
	}

	for _, idn := range idns {
		resp.IdentityNames = append(resp.IdentityNames, idn.Name)
	}

	for _, ver := range vers {
		resp.Verifiers = append(resp.Verifiers, &VerifierDetails{
			Name:           ver.Name,
			IdentityName:   ver.IdentityName,
			SupportRegular: ver.SupportRegular,
			SupportReverse: ver.SupportReverse,
			SupportOAuth2:  ver.SupportOAuth2,
			SupportStatic:  ver.SupportStatic,
		})
	}

	return resp, http.StatusOK
}

func (is *IdentitySvc) checkStatus(ctx context.Context) (interface{}, int) {
	sess := is.sessionObtain(ctx)

	resp, err := is.status(ctx, sess)
	if err != nil {
		return ErrorResp{
			Text: err.Error(),
		}, http.StatusInternalServerError
	}

	return resp, http.StatusOK
}

func (is *IdentitySvc) startSignIn(ctx context.Context) (interface{}, int) {
	sess := is.sessionObtain(ctx)

	if _, uid := sess.Info(); uid != "" {
		return ErrorResp{
			Text: "should be unauthenticated",
		}, http.StatusForbidden
	}

	if err := sess.StartAuthentication(ctx, identity.ObjectiveSignIn); err != nil {
		return ErrorResp{
			Text: err.Error(),
		}, http.StatusInternalServerError
	}

	resp, err := is.status(ctx, sess)
	if err != nil {
		return ErrorResp{
			Text: err.Error(),
		}, http.StatusInternalServerError
	}

	return resp, http.StatusOK
}

func (is *IdentitySvc) startSignUp(ctx context.Context) (interface{}, int) {
	sess := is.sessionObtain(ctx)

	if _, uid := sess.Info(); uid != "" {
		return ErrorResp{
			Text: "should be unauthenticated",
		}, http.StatusForbidden
	}

	if err := sess.StartAuthentication(ctx, identity.ObjectiveSignUp); err != nil {
		return ErrorResp{
			Text: err.Error(),
		}, http.StatusInternalServerError
	}

	resp, err := is.status(ctx, sess)
	if err != nil {
		return ErrorResp{
			Text: err.Error(),
		}, http.StatusInternalServerError
	}

	return resp, http.StatusOK
}

func (is *IdentitySvc) startAttach(ctx context.Context) (interface{}, int) {
	sess := is.sessionObtain(ctx)

	if _, uid := sess.Info(); uid != "" {
		return ErrorResp{
			Text: "should be unauthenticated",
		}, http.StatusForbidden
	}

	if err := sess.StartAuthentication(ctx, identity.ObjectiveAttach); err != nil {
		return ErrorResp{
			Text: err.Error(),
		}, http.StatusInternalServerError
	}

	resp, err := is.status(ctx, sess)
	if err != nil {
		return ErrorResp{
			Text: err.Error(),
		}, http.StatusInternalServerError
	}

	return resp, http.StatusOK
}

func (is *IdentitySvc) cancelAuthentication(ctx context.Context) (interface{}, int) {
	sess := is.sessionObtain(ctx)

	if err := sess.CancelAuthentication(ctx); err != nil {
		return ErrorResp{
			Text: err.Error(),
		}, http.StatusInternalServerError
	}

	resp, err := is.status(ctx, sess)
	if err != nil {
		return ErrorResp{
			Text: err.Error(),
		}, http.StatusInternalServerError
	}

	return resp, http.StatusOK
}

func (is *IdentitySvc) listMyIdentitiesAndVerifiers(ctx context.Context) (interface{}, int) {
	sess := is.sessionObtain(ctx)

	resp := &ListMyIdentitiesAndVerifiersResp{}

	idns, vers, err := sess.ListMyIdentitiesAndVerifiers(ctx)
	if err != nil {
		return ErrorResp{
			Text: err.Error(),
		}, http.StatusInternalServerError
	}

	for _, ver := range vers {
		if ver.Standalone {
			resp.Verifiers = append(resp.Verifiers, ver.Name)
		}
	}
	for _, idn := range idns {
		resp.Identities = append(resp.Identities, &IdentityData{
			Name:     idn.Name,
			Identity: idn.Identity,
		})
	}

	return resp, http.StatusOK
}

func (is *IdentitySvc) verify(ctx context.Context, requestData VerifyReq) (interface{}, int) {
	sess := is.sessionObtain(ctx)

	verErr := sess.Verify(ctx, requestData.VerifierName, requestData.VerificationCode, requestData.IdentityName, requestData.Identity)
	if verErr != nil {
		//TODO ???  error: status.New(codes.InvalidArgument, verErr.Error()).Err()
		return ErrorResp{
			Text: verErr.Error(),
		}, http.StatusBadRequest
	}

	stat, err := is.status(ctx, sess)
	if err != nil {
		return ErrorResp{
			Text: err.Error(),
		}, http.StatusInternalServerError
	}

	return stat, http.StatusOK
}

func (is *IdentitySvc) logout(ctx context.Context) (interface{}, int) {
	// TODO Also delete Authentication on logout

	// TODO
	panic("not implemented")

	return nil, 0
}

func (is *IdentitySvc) userMerge(ctx context.Context) (interface{}, int) {
	// TODO
	panic("not implemented")
	return nil, 0

}

////////////////////////////////////////////////////////////////
//// PrivateAuthenticationService
////

func (is *IdentitySvc) loginAs(ctx context.Context, requestData LoginAsReq) (interface{}, int) {
	sess := is.sessionObtain(ctx)

	sid, err := sess.LoginAs(requestData.User)
	if err != nil {
		return ErrorResp{
			Text: err.Error(),
		}, http.StatusInternalServerError
	}

	resp := LoginAsResp{
		User:    requestData.User,
		Session: sid,
	}

	return resp, http.StatusOK
}

////////////////////////////////////////////////////////////////
//// Helpers
////

func convertStatus(status identity.Status) *Status {
	s := Status{
		Token: status.Token,
	}

	if status.Authenticating != nil {
		au := &StatusAuthenticating{
			RemainingFactors: status.Authenticating.RemainingFactors,
		}

		if status.Authenticating.Objective != identity.ObjectiveSignIn &&
			status.Authenticating.Objective != identity.ObjectiveSignUp &&
			status.Authenticating.Objective != identity.ObjectiveAttach {
			panic("bad objective")
		}

		au.Objective = string(status.Authenticating.Objective)

		for _, fact := range status.Authenticating.CompletedFactors {
			au.CompletedFactors = append(au.CompletedFactors, StatusCompletedFactors{
				VerifierName: fact.VerifierName,
				IdentityName: fact.IdentityName,
				Identity:     fact.Identity,
			})
		}
		s.Authenticating = au
	}

	if status.Authenticated != nil {
		s.Authenticated = &StatusAuthenticated{
			User: status.Authenticated.User,
		}
	}

	return &s
}
