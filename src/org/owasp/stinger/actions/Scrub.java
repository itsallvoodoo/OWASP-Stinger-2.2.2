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

package org.owasp.stinger.actions;

import java.util.regex.Pattern;
import javax.servlet.http.HttpServletResponse;

import org.owasp.stinger.util.EntityEncoder;
import org.owasp.stinger.violation.Violation;
import org.owasp.stinger.http.MutableHttpRequest;

public class Scrub extends AbstractAction {
	
	private void scrubString(MutableHttpRequest request, String name, String value, String regex) {
		StringBuffer result = new StringBuffer();
		
		if(value != null && !"".equals(value)) {
			Pattern pattern = Pattern.compile(regex);
			for (int i=0;i<value.length(); i++){
				
				if (pattern.matcher(value.substring(i,i+1)).matches()){
					result.append(value.substring(i,i+1));
				}
			}
			request.replaceParameterValue(name, value, new String(result));
			System.out.println("Scrubbed " + name + ", from value: " + value + " to: " + new String(result));
		}
	}
	
	public void doAction(Violation violation, MutableHttpRequest request, HttpServletResponse response) {
		String name = null;
		String value = null;
		
		name = violation.getName();
		value = violation.getValue();
		String regex = violation.getRegEx();
		
		scrubString(request, name, value, regex);
	}
}
