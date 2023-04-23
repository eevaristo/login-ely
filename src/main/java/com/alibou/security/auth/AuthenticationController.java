package com.alibou.security.auth;

import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.alibou.security.user.User;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

  private final AuthenticationService service;

  @PostMapping("/register")
  public ResponseEntity<AuthenticationResponse> register(
      @RequestBody RegisterRequest request) {
    return ResponseEntity.ok(service.register(request));
  }

  @PostMapping("/authenticate")
  public ResponseEntity<AuthenticationResponse> authenticate(
      @RequestBody AuthenticationRequest request) {
    return ResponseEntity.ok(service.authenticate(request));
  }

  @PostMapping("/alterarSenha")
  public ResponseEntity<Object> alterarSenha(
      @RequestBody User user) {
    String msgAlteracao = service.alterarSenha(user);
    if (msgAlteracao == "Senha alterada com sucesso!") {
      return ResponseEntity.ok().body(msgAlteracao);
    } else if (msgAlteracao == "Senha atual está incorreta!") {
      return ResponseEntity.badRequest().body(msgAlteracao);
    } else {
      return ResponseEntity.badRequest().body(msgAlteracao);
    }
  }

}
