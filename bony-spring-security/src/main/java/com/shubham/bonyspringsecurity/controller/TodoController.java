package com.shubham.bonyspringsecurity.controller;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TodoController {

	private static final List<Todo> TODOS_LIST = List.of(new Todo("shubham", "Hello"),
			new Todo("shubham1", "Hello1"));

	@GetMapping("/todos")
	public List<Todo> getAllTodos() {
		return TODOS_LIST;
	}
	
	@GetMapping("users/{username}/todos")
	public Todo getTodoByUsername(@PathVariable("username") String username) {
		return TODOS_LIST.get(0);
	}
}

record Todo(String username, String description) {}