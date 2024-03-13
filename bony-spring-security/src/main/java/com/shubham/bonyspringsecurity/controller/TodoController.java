package com.shubham.bonyspringsecurity.controller;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TodoController {

	private static final List<Todo> TODOS_LIST = List.of(new Todo("shubham", "Hello"), new Todo("shubham1", "Hello1"));
	private Logger logger = LoggerFactory.getLogger(getClass());

	@GetMapping("/todos")
	public List<Todo> getAllTodos() {
		return TODOS_LIST;
	}

	@GetMapping("users/{username}/todos")
	public Todo getTodoByUsername(@PathVariable("username") String username) {
		return TODOS_LIST.get(0);
	}

	@PostMapping("users/{username}/todos")
	public void createTodoForSpecificUSer(@PathVariable("username") String username, @RequestBody Todo todo) {
		logger.info("Create {} for {}", todo, username);
	}
}

record Todo(String username, String description) {
}