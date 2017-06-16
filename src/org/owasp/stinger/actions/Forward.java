package org.owasp.stinger.actions;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.owasp.stinger.BreakChainException;
import org.owasp.stinger.http.MutableHttpRequest;
import org.owasp.stinger.violation.Violation;

public class Forward extends AbstractAction {

	public void doAction(Violation violation, MutableHttpRequest request, HttpServletResponse response) throws BreakChainException {
		String page = getParameter("page");
		
		try {
			request.getRequestDispatcher(page).forward(request, response);
		} catch (IOException ioe) {
			ioe.printStackTrace();
		} catch (ServletException se) {
			se.printStackTrace();
		}
	}
}
