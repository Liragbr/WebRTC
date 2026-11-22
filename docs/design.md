# Arquitetura e modelo de ameaças

| Componente | Responsabilidade e contrato |
|---|---|
| analyzer.capture | Valida a origem e o IP local, constrói argv e inicia TShark sem shell. Captura UDP sem modo promíscuo ou resolução DNS. Replay usa a mesma filtragem por destino e magic cookie. Entrega cada mapeamento ao consumidor. |
| analyzer.stun | Função pura para um datagrama completo. Valida tipo Binding success, cookie, tamanho total e limites de atributos TLV com alinhamento de quatro bytes. Decodifica o primeiro XOR-MAPPED-ADDRESS em IPv4 ou IPv6. |
| analyzer.enrichment | Normaliza IPs com ipaddress, compara a lista da sessão e implementa duas consultas HTTPS explícitas. |
| analyzer.gui | Tk pertence à thread principal. Uma thread coordena a captura e duas drenam stdout e stderr. A fila comporta 256 observações e a tabela preserva as 500 mais recentes. A GUI informa descartes por saturação ao encerrar normalmente. |
| analyzer.replay | CLI sem Tk, sem chamadas a provedores. Imprime uma linha por resposta aceita. Retransmissões podem repetir a transação. |

A captura ao vivo dura até 120 segundos. O controlador impõe prazo total de 135 segundos, inclusive no replay. Cancelamento ou expiração encerra o processo, aguarda até dois segundos e força o término se necessário. As threads são reunidas antes de liberar a sessão. O leitor de stderr retém somente a cauda da mensagem de diagnóstico. Uma nova captura exige o fim da anterior. A GUI executa HTTP em um processo separado com prazo externo de oito segundos, incluindo DNS. Ao fechar a janela, cancela a captura e recolhe o processo HTTP.

## Fronteiras de confiança

| Ameaça ou dado sensível | Controle | Risco residual |
|---|---|---|
| Entrada da GUI ou CLI altera comando/filtro | argv sem shell, IP canônico, interface validada e filtro definido pelo programa. PCAP como caminho absoluto de arquivo regular. | PATH, instalação do TShark e diretório de trabalho devem ser confiáveis. |
| Datagrama ou PCAP malformado | Validação estrutural no parser, prazo de execução e uso de TShark sem privilégios elevados na aplicação. | O dissecador nativo ainda processa conteúdo externo. Mantenha Wireshark atualizado. |
| Spoofing ou atribuição ao processo errado | Resultado descreve observação e divergência. Exige confirmação independente para um incidente. | Não há correlação de pedido/resposta, autenticação MESSAGE-INTEGRITY, validação FINGERPRINT ou atribuição por PID. |
| IPs expostos a terceiros | Geolocalização manual, IP unicast global, host HTTPS fixo, validação TLS padrão, sem redirects, leitura limitada a 8 KiB. | O provedor recebe o IP consultado e metadados da requisição. Geolocalização é aproximada. |
| Sobrecarga e retenção de dados | Fila e tabela limitadas, timeout, replay sem persistência automática. | Sob carga há perdas no sistema de captura ou na GUI. O arquivo PCAP e o redirecionamento de stdout ficam sob controle do operador. |

O destino do datagrama delimita o cliente em observação. A análise cobre respostas UDP STUN em claro com XOR-MAPPED-ADDRESS. Não inspeciona SDP, candidatos host/mDNS, STUN sobre TCP/TLS nem o conteúdo do canal de sinalização. A família do endereço mapeado pode diferir da família de transporte. O filtro de captura ao vivo depende do suporte da plataforma a BPF e da visibilidade da interface.
