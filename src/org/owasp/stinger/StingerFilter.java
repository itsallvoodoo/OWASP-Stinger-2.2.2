/**
 * Stinger is an HTTP Request Validation Engine
 * Copyright (C) 2006  Aspect Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Contact us at info@aspectsecurity.com or www.aspectsecurity.com
 *
 */

package org.owasp.stinger;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.owasp.stinger.http.MutableHttpRequest;
import org.owasp.stinger.rules.RuleSet;


public class StingerFilter implements Filter {
	
	private final static String POST = "POST";
	
	private final static String URL_FORM_ENCODING = "application/x-www-form-urlencoded";

        private Stinger stinger = null;
	
	private String config = null;

	private boolean reload = false;
	
	private RuleSet ruleSet = null;
	
	private String errorPage = null;
	
	public boolean debug = false;
	
	
	public void init(FilterConfig filterConfig) {
		System.out.println("Initializing Stinger");
		/** Load the the debug parm **/
		debug = Boolean.valueOf(filterConfig.getInitParameter("debug")).booleanValue();
		System.out.println("Debugging set to " + String.valueOf(debug));
		/** Pull config location from Filter init parameter **/
		config = filterConfig.getInitParameter("config");
		ruleSet = new RuleSet(config, debug);
		/** Error page to display when exceptions are thrown **/
		errorPage = filterConfig.getInitParameter("error-page");
		/** Should we dynamically load the ruleset? **/
		reload = Boolean.valueOf(filterConfig.getInitParameter("reload")).booleanValue();
		if (debug) System.out.println("Reload parm is: " + String.valueOf(reload));
		/** Get the stinger instance **/
		stinger = Stinger.getInstance(ruleSet, debug);
	}
	
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
		MutableHttpRequest mRequest = null;
		HttpServletResponse hResponse = null;
		
		
		if(request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			mRequest = new MutableHttpRequest((HttpServletRequest)request);
			hResponse = (HttpServletResponse)response;
			
			
			if(reload) {
				initRuleSet();
			}
			
			try {
				
				if(isValidRequest(mRequest)) {
                                    if(!ruleSet.isExcluded(mRequest.getRequestURI())) {
                                            stinger.validate(mRequest, hResponse);
                                    }

                                    if (debug)System.out.println("We're done processing, so do next filter in the chain");
                                    //mRequest.loadWLRequest(wlRequest);
                                    //wlRequest.setParameter("blah", "blah");
                                    chain.doFilter(mRequest, hResponse);
                                } else {
					System.out.println("[Stinger-Filter] caught a POST request with an incorrect content type header (" + mRequest.getContentType() + ") . Redirected to error page at " + errorPage);
					hResponse.sendRedirect(errorPage);
				} 
                        }
                        catch (BreakChainException bce) {
				bce.printStackTrace();
				try {
					hResponse.sendRedirect(errorPage);
				} catch (IOException ioe) {
					ioe.printStackTrace();
				}
			} catch(Exception e) {
				e.printStackTrace();
				
				try {
					hResponse.sendRedirect(errorPage);
				} catch (IOException ioe) {
					ioe.printStackTrace();
				}
			}
		}
	}

	/**
	 * MULTIPART VALIDATION BYPASS FIX:
	 * 
	 * The Stinger validation relies on the J2EE servlet framework.
	 * By default, the framework only supports standard url-form-encoding
	 * for POST requests. If a multipart request comes through, however,
	 * request.getParameterNames() will return an empty enumeration. As a
	 * quick fix, we do not currently accept multipart-form-encoded post
	 * requests.
	 * @param request
	 * @return
	 */
	private boolean isValidRequest(MutableHttpRequest request)
	{
		boolean valid = true;
		String method = request.getMethod();
		String header = request.getContentType();
		
		if(POST.equalsIgnoreCase(method) && !URL_FORM_ENCODING.equalsIgnoreCase(header))
		{
			valid = false;
		}
		
		return valid;
	}
        
	public void destroy() {
		
	}
	
	private synchronized void initRuleSet() {
		ruleSet = new RuleSet(config, debug);
		Stinger.setRuleSet(ruleSet);
	}
}
