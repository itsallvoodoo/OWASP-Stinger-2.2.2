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

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import java.util.Enumeration;
import java.util.LinkedList;
import java.util.Iterator;
import java.util.HashMap;

import org.owasp.stinger.actions.AbstractAction;
import org.owasp.stinger.http.MutableHttpRequest;
import org.owasp.stinger.rules.Rule;
import org.owasp.stinger.rules.CookieRule;
import org.owasp.stinger.rules.RuleSet;
import org.owasp.stinger.violation.Violation;
import org.owasp.stinger.violation.ViolationList;

public class Stinger {
	
	private static Stinger instance = new Stinger();
	
	private static RuleSet set = null;
	
	private static boolean debug = false;
	
	private Stinger() {
		
	}
	
	public static Stinger getInstance(RuleSet ruleSet, boolean debugIn) {
		setRuleSet(ruleSet);
		setDebug(debugIn);
		return instance;
	}
	
	public static void setRuleSet(RuleSet ruleSet) {
		set = ruleSet;
	}
	
	public static void setDebug(boolean debugIn) {
		debug = debugIn;
	}
	
	private void handleViolationActions(MutableHttpRequest request, HttpServletResponse response, Violation violation) throws BreakChainException {
		LinkedList actions = null;
		Iterator itr = null;
		AbstractAction action = null;
		
		actions = violation.getActions();
		itr = actions.iterator();
		
		while(itr.hasNext()) {
			action = (AbstractAction)itr.next();
			
			action.doAction(violation, request, response);
		}
	}
	
	private void handleViolations(MutableHttpRequest request, HttpServletResponse response, ViolationList vList) throws BreakChainException {
		Iterator itr = null;
		Violation violation = null;
		
		itr = vList.iterator();
		
		while(itr.hasNext()) {
			violation = (Violation)itr.next();
			if (debug) System.out.println("Handling violation " + violation.toString());
			
			handleViolationActions(request, response, violation);
		}
	}
	
	private void checkMissingCookies(MutableHttpRequest request, HttpServletResponse response, ViolationList vList) throws BreakChainException {
		String uri = request.getRequestURI();
		String name = null;
		Cookie[] cookies = null;
		CookieRule cRule = null;
		HashMap cookieMap = null;
		LinkedList cRules = null;
		Iterator itr = null;
		Violation violation = null;
		
		/** Check Missing Cookies **/
		cookies = request.getCookies();
		cookieMap = new HashMap();
		cRules = set.getCookieRules();
		
		if(cookies != null) {
			for(int i=0; i<cookies.length; i++) {
				cookieMap.put(cookies[i].getName(), cookies[i]);
			}
			itr = cRules.iterator();
			
			while(itr.hasNext()) {
				cRule = (CookieRule)itr.next();
				
				/** The cookie is considered missing if it DNE and we are NOT on the created URI **/
				/** Only enforce if we are in an enforcing uri **/
				
				if(!cookieMap.containsKey(cRule.getName()) && !cRule.isCreatedUri(uri) && cRule.isEnforced(uri)) {
					violation = new Violation(cRule.getMissing(), name, null, cRule.getPattern(), uri);
					
					if (debug) System.out.println("[Stinger-Filter] VIOLATION: Cookie " + cRule.getName() + " is missing");
					
					if(violation.getSeverity().equals(Severity.FATAL)) {
						handleViolationActions(request, response, violation);
						
						throw new BreakChainException("Chain broken due to fatal violation");
					} else if(violation.getSeverity().equals(Severity.CONTINUE)){
						vList.add(violation);
					} else {
						/** Severity == IGNORE **/
					}					
				}
			}
		} else {
			/** There exists no rules for this URI **/
			if (debug) System.out.println("[Stinger-Filter] Warning: There exists no cookie rules");
		}		
	}
	
	private void checkMalformedCookies(MutableHttpRequest request, HttpServletResponse response, ViolationList vList) throws BreakChainException {
		String uri = null;
		String name = null;
		Cookie cookie = null;
		Cookie[] cookies = null;
		CookieRule cRule = null;
		Violation violation = null;
		
		uri = request.getRequestURI();
		cookies = request.getCookies();
		
		if(cookies != null) {
			for(int i=0; i<cookies.length; i++) {
				cookie = cookies[i];
				cRule = set.getCookieRule(cookie.getName());
				
				if(cRule != null && cRule.isEnforced(uri)) {
					if(!cRule.isValid(cookie.getValue())) {
						violation = new Violation(cRule.getMissing(), name, cookie.getValue(), cRule.getPattern(), uri);
						
						if (debug) System.out.println("[Stinger-Filter] VIOLATION: Cookie " + cRule.getName() + " is malformed");
						
						if(violation.getSeverity().equals(Severity.FATAL)) {
							handleViolationActions(request, response, violation);
							
							throw new BreakChainException("Chain broken due to fatal violation");
						} else if(violation.getSeverity().equals(Severity.CONTINUE)){
							vList.add(violation);
						} else {
							/** Severity == IGNORE **/
						}					
					}
				}	
			}
		}		
	}
	
	private void checkMissingParameters(MutableHttpRequest request, HttpServletResponse response, ViolationList vList) throws BreakChainException {
		String uri = null;
		String name = null;
		Rule pRule = null;
		LinkedList pRules = null;
		Iterator itr = null;
		Violation violation = null;
		
		uri = request.getRequestURI();
		pRules = set.getParameterRules(uri);
		
		if(pRules != null) {
			itr = pRules.iterator();
			
			while(itr.hasNext()) {
				pRule = (Rule)itr.next();
				
				name = pRule.getName();
				
				if(!name.equals(RuleSet.STINGER_ALL) && (request.getParameter(name) == null || request.getParameter(name).equals(""))) {
					violation = new Violation(pRule.getMissing(), name, null, pRule.getPattern(), uri);
					
					if (debug) System.out.println("[Stinger-Filter] VIOLATION: Parameter " + name + " is missing");
					
					if(violation.getSeverity().equals(Severity.FATAL)) {
						
						handleViolationActions(request, response, violation);
						
						throw new BreakChainException("Chain broken due to fatal violation");
					} else if(violation.getSeverity().equals(Severity.CONTINUE)){
						vList.add(violation);
					} else {
						/** Severity == IGNORE **/
					}
				}
			}
		} else {
			/** There exists no rules for this uri **/
			if (debug) System.out.println("[Stinger-Filter] Warning: There exists no rules for the uri " + uri);
		}		
	}
	
	private void checkMalformedParameters(MutableHttpRequest request, HttpServletResponse response, ViolationList vList) throws BreakChainException {
		String uri = null;
		String name = null;
		String[] values = null;
		Rule pRule = null;
		Enumeration e = null;
		Violation violation = null;
		
		uri = request.getRequestURI();
		e = request.getParameterNames();
		
		while(e.hasMoreElements()) {
			name = (String)e.nextElement();
			values = request.getParameterValues(name);
			
			pRule = set.getParameterRule(uri, name);
			
			for (int i=0;i<values.length;i++){
				String value = values[i];
				if(pRule != null && !pRule.isValid(value)) {
					violation = new Violation(pRule.getMalformed(), name, value, pRule.getPattern(), uri);
					
					if (debug) System.out.println("[Stinger-Filter] VIOLATION: Parameter " + name + " is malformed");
					
					if(violation.getSeverity().equals(Severity.FATAL)) {
						handleViolationActions(request, response, violation);
						
						throw new BreakChainException("Chain broken due to fatal violation");
					} else if(violation.getSeverity().equals(Severity.CONTINUE)){
						vList.add(violation);
					} else {
						/** Severity == IGNORE **/
					}
				}
			}
		}	
	}
	
	private void checkMalformedUri(MutableHttpRequest request, HttpServletResponse response, ViolationList vList) throws BreakChainException {
		String uri = null;
		String name = null;
		String[] values = null;
		Rule pRule = null;
		Enumeration e = null;
		Violation violation = null;
		
		uri = request.getRequestURI();

		pRule = set.getParameterRule(uri, "uri");
		System.out.println("Checking uri: " + uri);
		String value = new String(request.getRequestURL());
		if(pRule != null && !pRule.isValid(value)) {
			violation = new Violation(pRule.getMalformed(), name, value, pRule.getPattern(), uri);
					
			if (debug) System.out.println("[Stinger-Filter] VIOLATION: Parameter " + name + " is malformed");
					
			if(violation.getSeverity().equals(Severity.FATAL)) {
				handleViolationActions(request, response, violation);
				
				throw new BreakChainException("Chain broken due to fatal violation");
			} else if(violation.getSeverity().equals(Severity.CONTINUE)){
				vList.add(violation);
			} else {
				/** Severity == IGNORE **/
			}
		}
	}
	
	public void validate(MutableHttpRequest request, HttpServletResponse response) throws BreakChainException {
		ViolationList vList = new ViolationList();
		
		vList = new ViolationList();
		
		checkMalformedUri(request, response, vList);
		checkMissingCookies(request, response, vList);
		checkMalformedCookies(request, response, vList);
		checkMissingParameters(request, response, vList);
		checkMalformedParameters(request, response, vList);
		
		/** No fatal violations, process actions for non-fatal violations **/
		if (debug)System.out.println("Now handle any stinger violations");
		handleViolations(request, response, vList);
	}
}
