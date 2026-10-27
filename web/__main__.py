import argparse
from pathlib import Path
from .app import create_app
from .config import CONFIG


def main():
    parser=argparse.ArgumentParser(description=CONFIG['name'])
    parser.add_argument('--host',default='127.0.0.1')
    parser.add_argument('--port',type=int,default=8776)
    parser.add_argument('--data-dir',type=Path)
    parser.add_argument('--public-origin')
    parser.add_argument('--demo',action='store_true')
    parser.add_argument('--no-auth',action='store_true')
    args=parser.parse_args()
    if args.no_auth and (args.host not in ('127.0.0.1','localhost') or args.public_origin):parser.error('--no-auth 仅用于本机预览')
    directory=args.data_dir or Path(__file__).resolve().parents[1]/'.local'/('web-demo' if args.demo else 'web')
    platform=None
    if args.demo:
        from .demo import DemoPlatform
        platform=DemoPlatform()
    app=create_app(directory,platform=platform,auth=not args.no_auth,public_origin=args.public_origin)
    if args.demo:
        from .demo import seed
        seed(app.extensions['workspace'])
    from .workspace_identity import install_identity
    def tenant_app(path):
        child=create_app(path, auth=False, public_origin=args.public_origin)
        child.extensions['operations'].start_worker()
        return child
    if not args.demo:
        install_identity(app, directory, CONFIG['slug'], tenant_app)
    app.extensions['operations'].start_worker()
    from waitress import serve
    print(f"{CONFIG['name']} http://{args.host}:{args.port}（{'演示' if args.demo else '真实'}模式）",flush=True)
    if not args.no_auth:print(f'访问密码保存在 {directory}/admin-password',flush=True)
    serve(app,host=args.host,port=args.port,threads=6)


if __name__=='__main__':main()
