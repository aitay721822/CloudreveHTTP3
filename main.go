package main

import (
	"context"
	_ "embed"
	"flag"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cloudreve/Cloudreve/v3/bootstrap"
	model "github.com/cloudreve/Cloudreve/v3/models"
	"github.com/cloudreve/Cloudreve/v3/pkg/cache"
	"github.com/cloudreve/Cloudreve/v3/pkg/conf"
	"github.com/cloudreve/Cloudreve/v3/pkg/util"
	"github.com/cloudreve/Cloudreve/v3/routers"

	"github.com/quic-go/quic-go/http3"
)

var (
	isEject    bool
	confPath   string
	scriptName string
)

//go:embed assets.zip
var staticZip string

var staticFS fs.FS

func init() {
	flag.StringVar(&confPath, "c", util.RelativePath("conf.ini"), "Path to the config file.")
	flag.BoolVar(&isEject, "eject", false, "Eject all embedded static files.")
	flag.StringVar(&scriptName, "database-script", "", "Name of database util script.")
	flag.Parse()

	staticFS = bootstrap.NewFS(staticZip)
	bootstrap.Init(confPath, staticFS)
}

func main() {
	// 关闭数据库连接
	defer func() {
		if model.DB != nil {
			model.DB.Close()
		}
	}()

	if isEject {
		// 开始导出内置静态资源文件
		bootstrap.Eject(staticFS)
		return
	}

	if scriptName != "" {
		// 开始运行助手数据库脚本
		bootstrap.RunScript(scriptName)
		return
	}

	api := routers.InitRouter()
	api.TrustedPlatform = conf.SystemConfig.ProxyHeader
	quicServer := &http3.Server{Handler: api}
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		quicServer.SetQuicHeaders(w.Header())
		api.ServeHTTP(w, r)
	})}

	// 收到信号后关闭服务器
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go shutdown(sigChan, httpServer, quicServer)

	defer func() {
		<-sigChan
	}()

	// 如果启用了SSL
	if conf.SSLConfig.CertPath != "" {
		util.Log().Info("Listening to %q", conf.SSLConfig.Listen)
		httpServer.Addr = conf.SSLConfig.Listen
		quicServer.Addr = conf.SSLConfig.Listen

		tcpErr := make(chan error)
		quicErr := make(chan error)
		go func() {
			tcpErr <- httpServer.ListenAndServeTLS(conf.SSLConfig.CertPath, conf.SSLConfig.KeyPath)
		}()
		go func() {
			quicErr <- quicServer.ListenAndServeTLS(conf.SSLConfig.CertPath, conf.SSLConfig.KeyPath)
		}()
		select {
		case err := <-tcpErr:
			util.Log().Error("Failed to listen to %q: %s", conf.SSLConfig.Listen, err)
			quicServer.Close()
			return 
		case err := <-quicErr:
			util.Log().Error("Failed to listen to %q: %s", conf.SSLConfig.Listen, err)
			return 
		}
	}

	// 如果启用了Unix
	if conf.UnixConfig.Listen != "" {
		// delete socket file before listening
		if _, err := os.Stat(conf.UnixConfig.Listen); err == nil {
			if err = os.Remove(conf.UnixConfig.Listen); err != nil {
				util.Log().Error("Failed to delete socket file: %s", err)
				return
			}
		}

		util.Log().Info("Listening to %q", conf.UnixConfig.Listen)
		if err := RunUnix(httpServer); err != nil {
			util.Log().Error("Failed to listen to %q: %s", conf.UnixConfig.Listen, err)
		}
		return
	}

	util.Log().Info("Listening to %q", conf.SystemConfig.Listen)
	httpServer.Addr = conf.SystemConfig.Listen
	if err := httpServer.ListenAndServe(); err != nil {
		util.Log().Error("Failed to listen to %q: %s", conf.SystemConfig.Listen, err)
	}
}

func RunUnix(server *http.Server) error {
	listener, err := net.Listen("unix", conf.UnixConfig.Listen)
	if err != nil {
		return err
	}

	defer listener.Close()
	defer os.Remove(conf.UnixConfig.Listen)

	if conf.UnixConfig.Perm > 0 {
		err = os.Chmod(conf.UnixConfig.Listen, os.FileMode(conf.UnixConfig.Perm))
		if err != nil {
			util.Log().Warning(
				"Failed to set permission to %q for socket file %q: %s",
				conf.UnixConfig.Perm,
				conf.UnixConfig.Listen,
				err,
			)
		}
	}

	return server.Serve(listener)
}

func shutdown(sigChan chan os.Signal, server *http.Server, quicServer *http3.Server) {
	sig := <-sigChan
	util.Log().Info("Signal %s received, shutting down server...", sig)
	ctx := context.Background()
	if conf.SystemConfig.GracePeriod != 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(conf.SystemConfig.GracePeriod)*time.Second)
		defer cancel()
	}

	// Shutdown quic server
	if err := quicServer.Close(); err != nil {
		util.Log().Error("Failed to shutdown quic server: %s", err)
	}

	// Shutdown http server
	if err := server.Shutdown(ctx); err != nil {
		util.Log().Error("Failed to shutdown server: %s", err)
	}

	// Persist in-memory cache
	if err := cache.Store.Persist(filepath.Join(model.GetSettingByName("temp_path"), cache.DefaultCacheFile)); err != nil {
		util.Log().Warning("Failed to persist cache: %s", err)
	}

	close(sigChan)
}
