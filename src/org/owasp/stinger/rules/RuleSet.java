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

package org.owasp.stinger.rules;

import java.io.File;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Iterator;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import org.owasp.stinger.Category;
import org.owasp.stinger.Severity;
import org.owasp.stinger.actions.AbstractAction;


public class RuleSet {
	
	/** Denotes a default ruleset **/
	public final static String STINGER_DEFAULT = "STINGER_DEFAULT";
	
	/** Denotes all parameters for a particular uri **/
	public final static String STINGER_ALL = "STINGER_ALL";
	
	/** The exclude-set which no protection will be applied **/
	private LinkedList excludeSet = new LinkedList();
	
	/** Double-Map of all parameter rules for a particular URI **/
	private HashMap pRules = new HashMap();
	
	/** Map of all cookie rules **/
	private HashMap cRules = new HashMap();
	
	/** Map of all regular expressions **/
	private HashMap regexs = new HashMap();
	
	private boolean debug = false;
	
	private Document parseXmlFile(String fileName) {
		Document doc = null;
		DocumentBuilderFactory bf = null;
		if (debug) System.out.println("Stinger SVDL: " + fileName);
		
		try {
			bf = DocumentBuilderFactory.newInstance();
			doc = bf.newDocumentBuilder().parse(new File(fileName));
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return doc;
	}
	
	private RuleSet() {
		
	}
	
	public RuleSet(String config, boolean debugIn) {
		debug = debugIn;
		parseRules(config);
	}
	
	private String getField(Element e, String key) {
		String field = null;
		Node n = null;
		
		if(e != null) {
			n = e.getElementsByTagName(key).item(0);
			
			if(n.getNodeType() == Node.ELEMENT_NODE) {
				e = (Element)n;
				
				field = getValue(e);
			}
		}
		
		return field;
	}
	
	private String getValue(Element e) {
		return e.getFirstChild().getNodeValue().trim();
	}
	
	private void parseParameters(Element e, AbstractAction action) {
		NodeList parameters = null;
		Node child = null;
		Element pe = null;
		String name = null;
		String value = null;
		
		parameters = e.getElementsByTagName("parameter");
		
		for(int i=0; i<parameters.getLength(); i++) {
			child = (Node)parameters.item(i);
			
			if(child.getNodeType() == Node.ELEMENT_NODE) {
				pe = (Element)child;
				
				name = getField(pe, "name");
				value = getField(pe, "value");
				
				action.setParameter(name, value);
			}
		}
	}
	
	private void parseActions(Element e, Rule rule, Category c) {
		NodeList actions = null;
		String className = null;
		Class actionClass = null;
		Object possibleAction = null;
		AbstractAction action = null;
		Node child = null;
		Element ae = null;
		
		actions = e.getElementsByTagName("action");
		
		for(int i=0; i<actions.getLength(); i++) {
			child = (Node)actions.item(i);
			
			if(child.getNodeType() == Node.ELEMENT_NODE) {
				ae = (Element)child;
				
				try {
					className = ae.getAttribute("class");
					actionClass = Class.forName(className);
					possibleAction = actionClass.newInstance();
					
					if(possibleAction instanceof AbstractAction) {
						action = (AbstractAction)possibleAction;
						
						parseParameters(ae, action);
						
						c.addAction(action);
					}
				} catch (ClassNotFoundException cnfe) {
					cnfe.printStackTrace();
				} catch (InstantiationException ie) {
					ie.printStackTrace();
				} catch (IllegalAccessException iae) {
					iae.printStackTrace();
				}
			}
		}
	}
	
	private void parseMissing(Element e, Rule rule) {
		Element miss = (Element)e.getElementsByTagName("missing").item(0);
		String severity = null;
		Category missing = null;
		
		severity = getField(miss, "severity");
		missing = new Category(Category.MISSING, Severity.valueOf(severity));
		
		parseActions(miss, rule, missing);
		
		rule.setMissing(missing);
	}
	
	private void parseMalformed(Element e, Rule rule) {
		Element mal = (Element)e.getElementsByTagName("malformed").item(0);
		String severity = null;
		Category malformed = null;
		
		severity = getField(mal, "severity");
		malformed = new Category(Category.MALFORMED, Severity.valueOf(severity));
		
		parseActions(mal, rule, malformed);
		
		rule.setMalformed(malformed);
	}
	
	private Pattern getPath(Element e) {
		String path = getField(e, "path");
		
		Pattern p = Pattern.compile(path);
		
		return p;
	}
	
	private void parseRules(String config) {
		Document d = parseXmlFile(config);
		if (debug) System.out.println(config);
		Element root = d.getDocumentElement();
		Element regexset = null;
		Element e = null;
		Element cookie = null;
		Element ruleSet = null;
		NodeList children = null;
		NodeList cookies = null;
		NodeList ruleSets = null;
		Node child = null;
		String name = null;
		String pattern = null;
		Rule pRule = null;
		CookieRule cRule = null;
		Pattern path = null;
		
		/** Parse Exclude Set **/
		if(root.getElementsByTagName("exclude-set").getLength() > 0) {
			Element excludeSetE = (Element)root.getElementsByTagName("exclude-set").item(0);
			NodeList excludeChildren = excludeSetE.getElementsByTagName("exclude");
			
			for(int i=0; i<excludeChildren.getLength(); i++) {
				Node n = (Node)excludeChildren.item(i);
				
				if(n.getNodeType() == Node.ELEMENT_NODE) {
					Element exclude = (Element)n;
					String uri = getValue(exclude);
					Pattern p = Pattern.compile(uri);
					
					excludeSet.add(p);
				}
			}
		}
		
		/** Parse RegExs **/
		regexset = (Element)root.getElementsByTagName("regexset").item(0);
		children = regexset.getElementsByTagName("regex");
		
		for(int i=0; i<children.getLength(); i++) {
			child = (Node)children.item(i);
			
			if(child.getNodeType() == Node.ELEMENT_NODE) {
				e = (Element)child;
				
				name = getField(e, "name");
				pattern = getField(e, "pattern");
				
				regexs.put(name, pattern);
			}
		}
		
		/** Parse Cookies **/
		cookies = root.getElementsByTagName("cookie");
		
		for(int i=0; i<cookies.getLength(); i++) {
			child = (Node)cookies.item(i);
			
			if(child.getNodeType() == Node.ELEMENT_NODE) {
				cookie = (Element)child;
				cRule = new CookieRule();
				
				cRule.setName(getField(cookie, "name"));
				cRule.setPattern((String)regexs.get(getField(cookie, "regex")));
				cRule.setCreated(getField(cookie, "created"));
				cRule.setEnforced(getField(cookie, "enforce"));
				
				/** Parse Missing **/
				parseMissing(cookie, cRule);
				
				/** Parse Malformed **/
				parseMalformed(cookie, cRule);
				
				/** Add Newly Parsed Cookie Rule **/
				cRules.put(cRule.getName(), cRule);
			}
		}
		
		/** Parse Rule Sets **/
		ruleSets = root.getElementsByTagName("ruleset");
		
		for(int i=0; i<ruleSets.getLength(); i++) {
			child = (Node)ruleSets.item(i);
			
			if(child.getNodeType() == Node.ELEMENT_NODE) {
				ruleSet = (Element)child;
				path = getPath(ruleSet);
				HashMap rules = new HashMap();
				
				children = ruleSet.getElementsByTagName("rule");
				
				for(int j=0; j<children.getLength(); j++) {
					child = (Node)children.item(j);
					
					if(child.getNodeType() == Node.ELEMENT_NODE) {
						e = (Element)child;
						pRule = new Rule();
						
						pRule.setName(getField(e, "name"));
						
						pattern = (String)regexs.get(getField(e, "regex"));
						
						/** If there exists no associated regex,
						 *  then use input as regex
						 */
						if(pattern == null) {
							pattern = getField(e, "regex");
						}
						
						pRule.setPattern(pattern);
						
						/** Parse Missing **/
						parseMissing(e, pRule);
						
						/** Parse Malformed **/
						parseMalformed(e, pRule);
						
						/** Add Newly Parsed Parameter Rule **/
						rules.put(pRule.getName(), pRule);
					}
				}
				
				pRules.put(path, rules);
			}
		}
	}
	
	public Rule getParameterRule(String uri, String parameterName) {
		Rule rule = null;
		HashMap uriRules = null;
		
		uriRules = getRules(uri);
		
		if(uriRules == null) {
			if (debug) System.out.println("[Stinger-Filter](Warning): using default parameter rule for parameter " + parameterName);
			uriRules = getRules(STINGER_DEFAULT);
			rule = (Rule)uriRules.get(STINGER_ALL);
		} else {
			rule = (Rule)uriRules.get(parameterName);
			
			/** If no rule exists for this particular URI, then get defaults **/
			if(rule == null) {
				rule = (Rule)uriRules.get(STINGER_ALL);
				
				/** No STINGER_ALL rule was defined for this URI, get Global Default **/
				if(rule == null) {
					uriRules = getRules(STINGER_DEFAULT);
					rule = (Rule)uriRules.get(STINGER_ALL);
				}
			}
		}
		
		return rule;
	}
	
	public HashMap getRules(String uri) {
		HashMap rules = null;
		Enumeration e = Collections.enumeration(pRules.keySet());
		
		while(e.hasMoreElements()) {
			Pattern p = (Pattern)e.nextElement();
			
			if(p.matcher(uri).matches()) {
				rules = (HashMap)pRules.get(p);
			}
		}
		
		return rules;
	}
	
	public LinkedList getParameterRules(String uri) {
		LinkedList result = null;
		Iterator itr = null;
		HashMap uriRules = null;
		String name = null;
		Rule rule = null;
		
		uriRules = getRules(uri);
		result = new LinkedList();
		
		if(uriRules != null) {
			itr = uriRules.keySet().iterator();
			
			while(itr.hasNext()) {
				name = (String)itr.next();
				rule = (Rule)uriRules.get(name);
				
				result.add(rule);
			}
		} else {
			/** Get Default Rules **/
			if (debug) System.out.println("[Stinger-Filter](WARNING): using default rules for uri " + uri);
			uriRules = getRules(STINGER_DEFAULT);
			
			result.add(uriRules.get(STINGER_ALL));
		}
		
		return result;
	}
	
	public CookieRule getCookieRule(String cookieName) {
		return (CookieRule)cRules.get(cookieName);
	}
	
	public LinkedList getCookieRules() {
		LinkedList result = null;
		Iterator itr = null;
		String name = null;
		
		result = new LinkedList();
		itr = cRules.keySet().iterator();
		
		while(itr.hasNext()) {
			name = (String)itr.next();
			
			result.add(cRules.get(name));
		}
		
		return result;
	}
	
	public HashMap getRegexs() {
		return regexs;
	}
	
	public void addParameterRule(String uri, Rule newRule) {
		Enumeration e = Collections.enumeration(pRules.keySet());
		boolean isSet = false;
		HashMap ruleSet = null;
		
		while(e.hasMoreElements()) {
			Pattern p = (Pattern)e.nextElement();
			
			if(p.matcher(uri).matches()) {
				ruleSet = (HashMap)pRules.get(p);
				ruleSet.put(newRule.getName(), newRule);
				isSet = true;
			}
		}
		
		if(isSet == false) {
			ruleSet = new HashMap();
			ruleSet.put(newRule.getName(), newRule);
			pRules.put(Pattern.compile(uri), ruleSet);
		}
	}
	
	public HashMap getParameterRules() {
		return pRules;
	}
	
	public boolean isExcluded(String uri) {
		Iterator itr = excludeSet.iterator();
		boolean isExcluded = false;
		
		while(itr.hasNext()) {
			Pattern p = (Pattern)itr.next();
			
			if(p.matcher(uri).matches()) {
				isExcluded = true;
				break;
			}
		}
		
		return isExcluded;
	}
}
