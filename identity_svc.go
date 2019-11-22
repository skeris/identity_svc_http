package identity_svc_http

import (
	"context"
	"fmt"
	"github.com/themakers/identity/cookie"
	"github.com/themakers/identity/identity"
	"log"
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
	public.HandleFunc("/ListSupportedIdentitiesAndVerifiers", is.ListSupportedIdentitiesAndVerifiers)
	public.HandleFunc("/CheckStatus", is.CheckStatus)
	public.HandleFunc("/StartSignIn", is.StartSignIn)
	public.HandleFunc("/StartSignUp", is.StartSignUp)
	public.HandleFunc("/StartAttach", is.StartAttach)
	public.HandleFunc("/CancelAuthentication", is.CancelAuthentication)
	public.HandleFunc("/ListMyIdentitiesAndVerifiers", is.ListMyIdentitiesAndVerifiers)
	public.HandleFunc("/Start", is.middleware(is.start))
	public.HandleFunc("/Verify", is.Verify)
	public.HandleFunc("/Logout", is.Logout)
	public.HandleFunc("/UserMerge", is.UserMerge)

	private = http.NewServeMux()
	private.HandleFunc("/LoginAs", is.LoginAs)

	return
}

func (is *IdentitySvc) middleware(f interface{}) http.HandlerFunc {
	fRefl := reflect.ValueOf(f)
	fReflType := fRefl.Type()

	var argType reflect.Type
	var argTypeRefl reflect.Value
	var argExist bool

	if fReflType.NumIn() > 1 {
		argExist = true
		argType = fReflType.In(1)
		argTypeRefl = reflect.New(argType)
	}

	return func(w http.ResponseWriter, q *http.Request) {
		q.Header.Set("Content-Type", "application/json")

		var fResultRefl []reflect.Value

		if argExist {
			arg := argTypeRefl.Interface()
			if err := json.NewDecoder(q.Body).Decode(&arg); err != nil {
				resp := ErrorResp{
					Text: err.Error(),
				}
				w.WriteHeader(http.StatusInternalServerError)
				if err := json.NewEncoder(w).Encode(resp); err != nil {
					panic(err)
				}
			} else {
				fResultRefl = fRefl.Call([]reflect.Value{reflect.ValueOf(q.Context()), reflect.ValueOf(arg)})
			}
		} else {
			fResultRefl = fRefl.Call([]reflect.Value{reflect.ValueOf(q.Context())})
		}

		w.WriteHeader(fResultRefl[1].Interface().(int))
		if err := json.NewEncoder(w).Encode(fResultRefl[0].Interface()); err != nil {
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

	return &StartResp{
		Directions: directions,
	}, http.StatusOK
}

func (is *IdentitySvc) Start1(w http.ResponseWriter, q *http.Request) {
	sess := is.sessionObtain(q.Context())

	var requestData StartReq
	if err := json.NewDecoder(q.Body).Decode(&requestData); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprint(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	ctx := q.Context()

	for k, v := range requestData.Values {
		ctx = context.WithValue(ctx, k, v)
	}

	directions, err := sess.Start(ctx, requestData.VerifierName, requestData.Args, requestData.IdentityName, requestData.Identity)
	if err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	resp := &StartResp{
		Directions: directions,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	q.Header.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

}

func (is *IdentitySvc) listSupportedIdentitiesAndVerifiers() (result interface{}, err error) {

	resp := VerifierDetailsResp{}

	idns, vers, err := sess.ListSupportedIdentitiesAndVerifiers()
	if err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
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

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	q.Header.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

func (is *IdentitySvc) ListSupportedIdentitiesAndVerifiers1(w http.ResponseWriter, q *http.Request) {
	sess := is.sessionObtain(q.Context())
	resp := VerifierDetailsResp{}

	idns, vers, err := sess.ListSupportedIdentitiesAndVerifiers()
	if err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
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

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	q.Header.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

func (is *IdentitySvc) CheckStatus(w http.ResponseWriter, q *http.Request) {
	log.Println("*** CheckStatus ***")

	sess := is.sessionObtain(q.Context())

	log.Println("*** CheckStatus ***", fmt.Sprintln(sess.Info()))

	if resp, err := is.status(q.Context(), sess); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	} else if err := json.NewEncoder(w).Encode(resp); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	q.Header.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

}

func (is *IdentitySvc) StartSignIn(w http.ResponseWriter, q *http.Request) {
	sess := is.sessionObtain(q.Context())

	if _, uid := sess.Info(); uid != "" {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "should be unauthenticated")
		w.WriteHeader(http.StatusInternalServerError)
	}

	if err := sess.StartAuthentication(q.Context(), identity.ObjectiveSignIn); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	}

	if resp, err := is.status(q.Context(), sess); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	} else if err := json.NewEncoder(w).Encode(resp); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	q.Header.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

func (is *IdentitySvc) StartSignUp(w http.ResponseWriter, q *http.Request) {
	sess := is.sessionObtain(q.Context())

	if _, uid := sess.Info(); uid != "" {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "should be unauthenticated")
		w.WriteHeader(http.StatusInternalServerError)
	}

	if err := sess.StartAuthentication(q.Context(), identity.ObjectiveSignUp); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	}

	if resp, err := is.status(q.Context(), sess); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	} else if err := json.NewEncoder(w).Encode(resp); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	q.Header.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

func (is *IdentitySvc) StartAttach(w http.ResponseWriter, q *http.Request) {
	sess := is.sessionObtain(q.Context())

	if _, uid := sess.Info(); uid != "" {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, "unauthenticated")
		w.WriteHeader(http.StatusInternalServerError)
	}

	if err := sess.StartAuthentication(q.Context(), identity.ObjectiveAttach); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	}

	if resp, err := is.status(q.Context(), sess); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	} else if err := json.NewEncoder(w).Encode(resp); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	q.Header.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

func (is *IdentitySvc) CancelAuthentication(w http.ResponseWriter, q *http.Request) {
	sess := is.sessionObtain(q.Context())

	if err := sess.CancelAuthentication(q.Context()); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	}

	if resp, err := is.status(q.Context(), sess); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	} else if err := json.NewEncoder(w).Encode(resp); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	q.Header.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

func (is *IdentitySvc) ListMyIdentitiesAndVerifiers(w http.ResponseWriter, q *http.Request) {
	sess := is.sessionObtain(q.Context())

	resp := &ListMyIdentitiesAndVerifiersResp{}

	idns, vers, err := sess.ListMyIdentitiesAndVerifiers(q.Context())
	if err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
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

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	q.Header.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

func (is *IdentitySvc) Verify(w http.ResponseWriter, q *http.Request) {
	sess := is.sessionObtain(q.Context())

	var requestData VerifyReq
	if err := json.NewDecoder(q.Body).Decode(&requestData); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	verErr := sess.Verify(q.Context(), requestData.VerifierName, requestData.VerificationCode, requestData.IdentityName, requestData.Identity)

	if stat, err := is.status(q.Context(), sess); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	} else if err := json.NewEncoder(w).Encode(stat); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	q.Header.Set("Content-Type", "application/json")

	if verErr != nil {
		//TODO ???  error: status.New(codes.InvalidArgument, verErr.Error()).Err()
		w.WriteHeader(http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
	}
}

func (is *IdentitySvc) Logout(w http.ResponseWriter, q *http.Request) {
	sess := is.sessionObtain(q.Context())

	// TODO Also delete Authentication on logout

	// TODO
	panic("not implemented")

	if resp, err := is.status(q.Context(), sess); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	} else if err := json.NewEncoder(w).Encode(resp); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	q.Header.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

func (is *IdentitySvc) UserMerge(w http.ResponseWriter, q *http.Request) {
	// TODO
	panic("not implemented")

}

////////////////////////////////////////////////////////////////
//// PrivateAuthenticationService
////

func (is *IdentitySvc) LoginAs(w http.ResponseWriter, q *http.Request) {
	sess := is.sessionObtain(q.Context())

	var requestData LoginAsReq
	if err := json.NewDecoder(q.Body).Decode(&requestData); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	sid, err := sess.LoginAs(requestData.User)
	if err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
	}

	resp := LoginAsResp{
		User:    requestData.User,
		Session: sid,
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		q.Header.Set("Content-Type", "text/plain")
		fmt.Fprintln(w, err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		panic(err)
	}

	q.Header.Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
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
