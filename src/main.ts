import '@gershy/clearing';
import type http                           from '@gershy/util-http';
import type retry from '@gershy/util-retry';

type OptionalProps<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

// TODO: These are completely stubbed... need to fix
type HttpArgs<A, B> = any;
type HttpReq = { query: any, body: any };
type HttpRes = any;

export type HttpOauthArgs<Req extends HttpReq, Res extends HttpRes> = {
  
  inject: {
    http: typeof http,
    retry: typeof retry
  },
  
  // Full http args to make a token request
  tokenHttpArgs: HttpArgs<Req, Res> & Pick<Req, 'query' | 'body'>,
  
  // Function to extract token and expiry ms from http response
  tokenExtract: (res: Res) => { expiryMs: number, token: string },
  
  // Function to inject token into outgoing authenticated http request
  tokenInject: <T extends HttpArgs<HttpReq, HttpRes>>(token: string, req: T) => T,
  
  // Function to detect if incoming authenticated response indicates authentication failure
  isUnauthenticatedRes: (res: any) => boolean
  
};
export default class HttpOauth<Req extends HttpReq, Res extends HttpRes> {
  
  protected static invalidBearerToken = { expiryMs: -Infinity, token: '' };
  
  protected inject: {
    http: typeof http,
    retry: typeof retry
  };
  protected args: HttpOauthArgs<Req, Res>;
  protected bearerToken: { expiryMs: number, token: string } | Promise<{ expiryMs: number, token: string }>;
  
  constructor(args: HttpOauthArgs<Req, Res>) {
    this.inject = args.inject;
    this.args = args;
    this.bearerToken = HttpOauth.invalidBearerToken;
  }
  
  protected async getBearerToken() {
    
    const bt = this.bearerToken;
    const bearerToken = cl.isCls(bt, Promise) ? await bt : bt;
    if (Date.now() < bearerToken.expiryMs) return bearerToken.token;
    
    const httpArgs = this.args.tokenHttpArgs;
    this.bearerToken = this.inject.http(httpArgs).then(res => {
      
      const { expiryMs, token } = this.args.tokenExtract(res as any);
      const now = Date.now();
      const remainingMs = expiryMs - now;
      
      return this.bearerToken = {
        expiryMs: now + (remainingMs * 0.95 - 1500), // Eagerly expire the token
        token
      };
      
    });
    
    return this.bearerToken.then(v => v.token);
    
  }
  
  public async http<Req extends HttpReq, Res extends HttpRes>(args: OptionalProps<HttpArgs<Req, Res>, '$req' | '$res' | 'netProc'>): Promise<Res> {
    
    return this.inject.retry({
      attempts: 3,
      fn: async () => {
        
        const token = await this.getBearerToken();
        const httpAuthArgs = this.args.tokenInject(token, {
          ...this.args.tokenHttpArgs[cl.slice]([ 'netProc' ]),
          ...args
        } as any);
        
        const res = await this.inject.http(httpAuthArgs).catch(err => {
          if (/^http (?:reject|glitch)$/.test(err.message)) return err;
          throw err;
        });
        
        if (this.args.isUnauthenticatedRes(res)) {
          this.bearerToken = HttpOauth.invalidBearerToken;
          throw Error('unauthenticated')[cl.mod]({ retry: true });
        }
        
        return res;
        
      }
    }).then(r => r.val as any);
    
  }
  
};
