<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
	pageEncoding="ISO-8859-1"%>
<!-- 
<%@ page import="org.owasp.stinger.violation.*,java.util.*"%>
-->
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Stinger Test Page</title>
</head>
<body>
<h3>Welcome to the Stinger Test Page</h3>
<%
	String username = request.getParameter("username");
	String password = request.getParameter("password");
	String hidden1 = request.getParameter("hidden1");
	String html = request.getParameter("html");

	out.println("JSESSIONID: " + session.getId() + " <br/>");
	out.println("Total Parameters: " + request.getParameterMap().size() + "<br/>");

	if (username != null) {
		out.println("Username = " + username + "<br/>");
	}

	if (password != null) {
		out.println("Password = " + password + " <br/>");
	}

	if (hidden1 != null) {
		out.println("Hidden1 = " + hidden1 + "<br/>");
	}

	if (html != null) {
		out.println("HTML = " + html + "<br/>");
	}
%>
<br />
<form name="myform" method="POST">
<input type="text" name="username" /><br />
<input type="password" name="password" /><br />
<input type="submit" name="submit" /><br />
<input type="hidden" name="hidden1" /><br />
<label>Display some HTML</label><br />
<textarea name="html" cols=40 rows=6></textarea></form>
</body>
</html>
