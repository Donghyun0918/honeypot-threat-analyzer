output "public_ip" {
  description = "Elastic IP"
  value       = aws_eip.app.public_ip
}

output "dashboard_url" {
  value = "http://${aws_eip.app.public_ip}:8002"
}

output "tpot_web_url" {
  description = "T-Pot 웹(Kibana · 어택맵). admin_cidrs 에서만 열린다 — 비어 있으면 tpot_web_tunnel 로"
  value       = var.honeypot ? "https://${aws_eip.app.public_ip}:64297" : null
}

output "tpot_web_tunnel" {
  description = "관리 포트를 열지 않고 T-Pot 웹 보기 — 실행 후 https://localhost:64297"
  value       = var.honeypot ? "aws ssm start-session --region ${var.region} --target ${aws_instance.app.id} --document-name AWS-StartPortForwardingSession --parameters portNumber=64297,localPortNumber=64297" : null
}

output "tpot_web_password" {
  description = "T-Pot 웹 비밀번호 확인(사용자 이름은 tpot_web_user)"
  value       = var.honeypot ? "aws ssm get-parameter --region ${var.region} --with-decryption --name ${var.ssm_prefix}/tpot_web_password --query Parameter.Value --output text" : null
}

output "instance_id" {
  value = aws_instance.app.id
}

output "ssm_session" {
  description = "SSH 없이 셸 열기"
  value       = "aws ssm start-session --region ${var.region} --target ${aws_instance.app.id}"
}

output "bootstrap_log" {
  description = "부트스트랩 진행 확인(서버 안에서). honeypot 이면 중간에 한 번 재부팅된다"
  value       = "sudo tail -f /var/log/jsp-bootstrap.log"
}
