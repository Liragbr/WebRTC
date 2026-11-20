# WebRTC · analisador de respostas STUN

Ferramenta de diagnóstico para verificar quais endereços de saída um servidor STUN informa a um cliente sob teste. Funciona com captura local via TShark e replay de PCAP sem interface gráfica. Cada observação contém a transação STUN, o endereço mapeado, a porta e a comparação com as saídas previstas pelo operador.

## Executar

Use Python 3.11 ou superior e TShark 4.x. A interface gráfica também requer Tk. No Ubuntu, os pacotes de sistema são `tshark` e `python3-tk`. No Windows, instale Wireshark com TShark e Npcap. O aplicativo procura TShark no PATH e, no Windows, também no diretório padrão do Wireshark. O runtime Python usa apenas a biblioteca padrão.

```sh
tshark --version
tshark -D
python STUN.py
```

Escolha o índice da interface e o IP local que recebe as respostas. Em uma captura dentro do túnel, esse IP pode pertencer à interface virtual. Informe os IPs de saída previstos pela política ou deixe o campo vazio para inventário. A política fica fixa durante a sessão. Use as permissões de captura da plataforma para o usuário da sessão. O replay funciona sem privilégios de captura.

A consulta opcional ao ipify preenche o campo de referência com **uma** saída HTTPS. Verifique esse valor contra a política antes de iniciar. Selecionar uma linha e acionar a consulta ao ipinfo.io envia aquele IP ao provedor para obter localização aproximada e organização. Uma sessão padrão faz zero consultas HTTP.

## Reproduzir uma análise

```sh
python -m tests.fixture controlled.pcap
python -m analyzer.replay controlled.pcap --local 192.0.2.10 --expected 198.51.100.7
```

Saída esperada, na ordem do arquivo:

```text
000102030405060708090a0c 198.51.100.7 3478 saída prevista
000102030405060708090a0b 203.0.113.9 3478 divergência de saída (investigar)
```

Os endereços são reservados para documentação. O PCAP contém cinco datagramas. A seleção do cliente exclui a resposta a outro destino. O parser descarta a resposta truncada e o UDP sem STUN.

## Interpretar uma observação

| Resultado | Evidência |
|---|---|
| Observado, sem referência | O servidor informou um mapeamento. Falta a política de saída para compará-lo. |
| Saída prevista | O IP mapeado consta na lista da sessão. A conclusão vale para essa resposta. |
| Divergência de saída | O IP ficou fora da lista. Investigue interface, família IP, rotas, atribuição ao aplicativo e política de split tunnel. |
| Nenhuma linha | A captura não encontrou uma resposta compatível. TURN, transporte cifrado, ausência de tráfego ou interface incorreta são possíveis explicações. |

Para confirmar vazamento, estabeleça qual destinatário ficou sabendo de qual IP e qual política proibia essa divulgação. Uma resposta STUN isolada não prova que um site recebeu um candidato ICE, que houve conexão com um peer ou que um navegador específico originou o tráfego.

## Verificar o projeto

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
ruff check .
ruff format --check .
bandit -q -r analyzer STUN.py
tshark --version
python -m unittest discover -v
```

No PowerShell, ative o ambiente com `.venv\Scripts\Activate.ps1`. O teste de PCAP indica skip quando falta TShark. A CI exige o executável, roda a suíte em Python 3.11 e 3.13 e abre e fecha a GUI em um display virtual Linux.

[Arquitetura e ameaças](docs/design.md) · [Cenários e evidências](docs/validation.md)
