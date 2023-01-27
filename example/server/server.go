package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	hertzServer "github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/adaptor"
	"github.com/josephGuo/fastsession"
	"github.com/josephGuo/oauth2/errors"
	"github.com/josephGuo/oauth2/generates"
	"github.com/josephGuo/oauth2/manage"
	"github.com/josephGuo/oauth2/models"
	"github.com/josephGuo/oauth2/server"
	"github.com/josephGuo/oauth2/store"
)

var (
	dumpvar   bool
	idvar     string
	secretvar string
	domainvar string
	portvar   int
)

func init() {
	flag.BoolVar(&dumpvar, "d", true, "Dump requests and responses")
	flag.StringVar(&idvar, "i", "222222", "The client id being passed in")
	flag.StringVar(&secretvar, "s", "22222222", "The client secret being passed in")
	flag.StringVar(&domainvar, "r", "http://localhost:9094", "The domain of the redirect url")
	flag.IntVar(&portvar, "p", 9096, "the base port for the server")
}

func main() {
	flag.Parse()
	if dumpvar {
		log.Println("Dumping requests")
	}
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	// token store
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	// generate jwt access token
	// manager.MapAccessGenerate(generates.NewJWTAccessGenerate("", []byte("00000000"), jwt.SigningMethodHS512))
	manager.MapAccessGenerate(generates.NewAccessGenerate())

	clientStore := store.NewClientStore()
	clientStore.Set(idvar, &models.Client{
		ID:     idvar,
		Secret: secretvar,
		Domain: domainvar,
	})
	manager.MapClientStorage(clientStore)

	srv := server.NewServer(server.NewConfig(), manager)

	srv.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (userID string, err error) {
		if username == "test" && password == "test" {
			userID = "test"
		}
		return
	})

	srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})
	h := hertzServer.Default(hertzServer.WithHostPorts("127.0.0.1:8000"), hertzServer.WithExitWaitTime(3*time.Second))
	h.Use(fastsession.NewHertzSession("memory", "oauth2server_hertz_id"))
	h.LoadHTMLGlob("./static/*")
	h.Any("/login", loginHandler)
	h.Any("/auth", authHandler)

	h.Any("/oauth/authorize", func(c context.Context, ctx *app.RequestContext) {
		r, _ := adaptor.GetCompatRequest(&ctx.Request)
		if dumpvar {
			dumpRequest(os.Stdout, "authorize", r)
		}

		session := fastsession.DefaultSession(ctx)
		store := fastsession.DefaultStore(ctx)
		if session == nil || store == nil {

			//http.Error(w, err.Error(), http.StatusInternalServerError)
			ctx.AbortWithError(http.StatusInternalServerError, errors.New("fastsession hav't init"))
			return
		}

		var form url.Values
		if v := store.Get("ReturnUri"); v != nil {
			form = v.(url.Values)
		}
		r.Form = form

		store.Delete("ReturnUri")
		session.Save(ctx, store)

		err := srv.HandleAuthorizeRequest(c, ctx)
		if err != nil {
			//http.Error(w, err.Error(), http.StatusBadRequest)
			ctx.AbortWithError(http.StatusBadRequest, err)
		}
	})

	h.Any("/oauth/token", func(c context.Context, ctx *app.RequestContext) {
		r, _ := adaptor.GetCompatRequest(&ctx.Request)
		if dumpvar {
			_ = dumpRequest(os.Stdout, "token", r) // Ignore the error
		}

		err := srv.HandleTokenRequest(c, ctx)
		if err != nil {
			//http.Error(w, err.Error(), http.StatusInternalServerError)
			ctx.AbortWithError(http.StatusInternalServerError, err)
		}
	})

	h.Any("/test", func(c context.Context, ctx *app.RequestContext) {
		r, _ := adaptor.GetCompatRequest(&ctx.Request)
		if dumpvar {
			_ = dumpRequest(os.Stdout, "test", r) // Ignore the error
		}
		token, err := srv.ValidationBearerToken(c, &ctx.Request)
		if err != nil {
			//http.Error(w, err.Error(), http.StatusBadRequest)
			ctx.AbortWithError(http.StatusBadRequest, err)
			return
		}

		data := map[string]interface{}{
			"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
			"client_id":  token.GetClientID(),
			"user_id":    token.GetUserID(),
		}
		// e := json.NewEncoder(w)
		// e.SetIndent("", "  ")
		// e.Encode(data)
		ctx.IndentedJSON(200, data)
	})

	log.Printf("Server is running at %d port.\n", portvar)
	log.Printf("Point your OAuth client Auth endpoint to %s:%d%s", "http://localhost", portvar, "/oauth/authorize")
	log.Printf("Point your OAuth client Token endpoint to %s:%d%s", "http://localhost", portvar, "/oauth/token")
	// log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", portvar), nil))
}

func dumpRequest(writer io.Writer, header string, r *http.Request) error {
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		return err
	}
	writer.Write([]byte("\n" + header + ": \n"))
	writer.Write(data)
	return nil
}

func userAuthorizeHandler(c context.Context, ctx *app.RequestContext) (userID string, err error) {
	r, _ := adaptor.GetCompatRequest(&ctx.Request)
	if dumpvar {
		_ = dumpRequest(os.Stdout, "userAuthorizeHandler", r) // Ignore the error
	}
	session := fastsession.DefaultSession(ctx)
	store := fastsession.DefaultStore(ctx)
	if err != nil {
		return
	}

	uid := store.Get("LoggedInUserID")
	if uid != nil {
		if r.Form == nil {
			r.ParseForm()
		}

		store.Set("ReturnUri", r.Form)
		session.Save(ctx, store)

		ctx.Response.Header.Set("Location", "/login")
		ctx.Response.Header.SetStatusCode(http.StatusFound)
		return
	}

	userID = uid.(string)
	store.Delete("LoggedInUserID")
	session.Save(ctx, store)
	return
}

func loginHandler(c context.Context, ctx *app.RequestContext) {
	r, _ := adaptor.GetCompatRequest(&ctx.Request)
	if dumpvar {
		_ = dumpRequest(os.Stdout, "login", r) // Ignore the error
	}
	session := fastsession.DefaultSession(ctx)
	store := fastsession.DefaultStore(ctx)
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }

	if r.Method == "POST" {
		if r.Form == nil {
			if err := r.ParseForm(); err != nil {
				//http.Error(w, err.Error(), http.StatusInternalServerError)
				ctx.AbortWithError(http.StatusInternalServerError, err)
				return
			}
		}
		store.Set("LoggedInUserID", r.Form.Get("username"))
		session.Save(ctx, store)

		ctx.Response.Header.Set("Location", "/auth")
		ctx.Response.Header.SetStatusCode(http.StatusFound)
		return
	}
	ctx.HTML(200, "static/login.html", nil)
	//outputHTML(w, r, "static/login.html")
}

func authHandler(c context.Context, ctx *app.RequestContext) {
	r, _ := adaptor.GetCompatRequest(&ctx.Request)
	if dumpvar {
		_ = dumpRequest(os.Stdout, "auth", r) // Ignore the error
	}
	//session := fastsession.DefaultSession(ctx)
	store := fastsession.DefaultStore(ctx)
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusInternalServerError)
	// 	return
	// }

	if val := store.Get("LoggedInUserID"); val == nil {
		ctx.Response.Header.Set("Location", "/login")
		ctx.Response.SetStatusCode(http.StatusFound)
		return
	}

	//outputHTML(w, r, "static/auth.html")
	ctx.HTML(200, "static/login.html", nil)
}

func outputHTML(w http.ResponseWriter, req *http.Request, filename string) {
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer file.Close()
	fi, _ := file.Stat()
	http.ServeContent(w, req, file.Name(), fi.ModTime(), file)
}
