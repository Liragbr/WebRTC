# Evidências e critérios de confirmação

## Replay controlado

Gere o PCAP e rode o comando do README. O gerador usa bytes fixos, timestamps fixos e endereços de documentação. O teste de integração chama o executável TShark e a CLI pública. A tabela descreve quatro políticas aplicadas à mesma sequência de duas respostas locais.

| Cenário modelado | --expected | Primeira resposta | Segunda resposta |
|---|---|---|---|
| Inventário sem política | vazio | observada | observada |
| Túnel integral exige saída A | 198.51.100.7 | prevista | divergente |
| Saídas A e B permitidas | 198.51.100.7,203.0.113.9 | prevista | prevista |
| Rede direta exige saída B | 203.0.113.9 | divergente | prevista |

Os testes unitários incluem um vetor IPv6 derivado da seção 2.3 da RFC 5769, padding, truncamento e erro de comprimento. O teste de transporte usa datagramas IPv4. Os testes do controlador iniciam processos reais para verificar timeout, cancelamento e erro com diagnóstico. As consultas HTTP são simuladas.

## Validação em rede própria

O replay verifica a lógica de interpretação. Uma conclusão sobre VPN, navegador ou política real exige uma coleta própria. Registre versão do navegador e do TShark, horário, política esperada por família IP, interfaces física e virtual, rotas e endpoint STUN de teste. Evite usar a saída HTTPS como única referência.

1. Em rede direta, gere uma negociação ICE controlada e registre o IP observado pelo servidor STUN do laboratório. Correlacione a transação e a porta com o PCAP do cliente.
2. Repita com túnel integral. Registre as saídas autorizadas IPv4 e IPv6 e capture na interface onde o UDP STUN é visível. Uma resposta da saída direta, confirmada pelo servidor fora da política, evidencia exposição ao servidor.
3. Repita com split tunnel e documente a regra aplicada ao destino. A mesma saída direta pode ser permitida nesse cenário.
4. Se a hipótese envolver divulgação ao site ou peer, registre os candidatos entregues ao destinatário no canal de sinalização do laboratório e correlacione sessão, horário e endereço. Se envolver conexão direta, registre também o par ICE selecionado.

Arquive política, comandos, hashes dos PCAPs e evidência do destinatário. Informe explicitamente o que faltou observar quando a conclusão for inconclusiva. Os cenários acima constituem um roteiro de campo. O repositório distribui apenas dados sintéticos.

## Referências

- [RFC 8489, atributos STUN e XOR-MAPPED-ADDRESS](https://www.rfc-editor.org/rfc/rfc8489.html#section-14.2)
- [RFC 5769, vetores STUN](https://www.rfc-editor.org/rfc/rfc5769.html#section-2.3)
- [RFC 8445, ICE](https://www.rfc-editor.org/rfc/rfc8445.html)
- [Manual do TShark](https://www.wireshark.org/docs/man-pages/tshark.html)
