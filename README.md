# Easy PKG Extractor

Programa portátil para Windows que lê, extrai e organiza arquivos `.pkg` compatíveis com o formato usado por portes recentes de jogos para PC.

> **Importante:** ele não extrai qualquer arquivo `.pkg`. O programa foi feito para PKGs de PS4 compatíveis com o formato **fake PKG 5.05+**. PKGs oficiais da Sony com criptografia de fábrica são identificados e ignorados.

## Download

Baixe a versão pronta para usar na página de [Releases](https://github.com/gustasrod/easy-pkg-extractor/releases/latest):

`easy-pkg-extractor-windows-x64.zip`

O pacote contém o executável `easy-pkg-extractor.exe`. Não é necessário instalar Python.

## Como usar

1. Extraia o ZIP.
2. Coloque `easy-pkg-extractor.exe` na pasta do launcher, junto dos arquivos `.pkg`, ou escolha outra pasta para os PKGs.
3. Abra o programa. Assim que inicia, ele procura automaticamente arquivos `.pkg` na pasta onde `easy-pkg-extractor.exe` está salvo e em todas as subpastas.
4. Confira a lista de arquivos encontrados. Para repetir a busca nessa mesma pasta, clique em **Search .pkg in this folder**.
5. Deixe **All packages in the list** marcado para extrair tudo ou marque **Only selected packages** para escolher pacotes específicos.
6. Clique em **Extract and Organize**.

Também é possível usar **Add files...** para escolher arquivos individuais ou **Add another folder...** para adicionar outra pasta.

A seleção é feita por **PKG inteiro**. O programa não seleciona arquivos internos de um PKG.

A interface do programa está em inglês.

![Exemplo da interface](docs/images/exemplo-interface.png)

*Exemplo da lista de PKGs analisados e das opções de extração.*

## Quais PKGs são compatíveis?

### O que significa “fake PKG 5.05+”

Esse é o nome usado pela comunidade para uma família de PKGs de PS4 que usa uma estrutura e chaves compatíveis com o ambiente de firmware 5.05 ou mais recente.

- **Fake** não quer dizer “jogo falso”. É o nome do formato do pacote.
- **5.05+** se refere ao firmware do PS4, não à versão do Windows ou do jogo para PC.
- O programa foi feito para esse tipo de PKG e precisa das informações internas esperadas para conseguir extrair os arquivos.

PKGs oficiais da Sony com criptografia de fábrica não são suportados. Eles aparecem como **Official encryption** ou **Criptografia oficial** e são ignorados para evitar travamentos.

Mesmo dentro do formato compatível, o arquivo precisa estar completo e não pode ter sido alterado durante a leitura. Uma versão incompleta, corrompida ou com uma variação não suportada pode apresentar erro.

## Como os arquivos são organizados

Na opção normal, escolha uma **Output folder** (pasta de saída). O programa cria uma subpasta com ponto no começo usando o título identificado no PKG do jogo base.

Com um PKG de jogo base na lista e **Join game and update** ativado — essa opção vem ativada por padrão — o resultado fica assim:

```text
pasta de saída\
└─ .NomeDoJogo\
   ├─ CUSAxxxxx\
   │  └─ arquivos do jogo base e das atualizações\
   └─ addcont\
      └─ CUSAxxxxx\
         └─ ID_DO_DLC\
            └─ arquivos do DLC\
```

O jogo base é processado primeiro. Depois, as atualizações são processadas da versão mais antiga para a mais nova. Os DLCs e extras são processados depois e ficam separados em `addcont`.

Se **Join game and update** for desativado, a atualização fica em uma pasta separada:

```text
pasta de saída\
└─ .NomeDoJogo\
   ├─ CUSAxxxxx\
   ├─ CUSAxxxxx-patch\
   └─ addcont\
      └─ CUSAxxxxx\
         └─ ID_DO_DLC\
```

O exemplo abaixo mostra essa organização com `CUSA08809`, `CUSA08809-patch` e `addcont` no mesmo nível:

![Exemplo das pastas geradas](docs/images/exemplo-pastas.png)

*Exemplo real da organização criada pelo programa.*

Se a lista não tiver um PKG de jogo base identificado, o nome `.NomeDoJogo` não poderá ser criado. Nesse caso, o programa avisa no histórico e usa o código do jogo, como `CUSAxxxxx`, para jogo base ou atualização; DLCs continuam em `addcont`.

### Extrair na pasta do programa

Ao marcar **Extract into the program folder**, a pasta de saída escolhida é ignorada e os arquivos são gravados ao lado do executável.

Esse modo não cria a subpasta `.NomeDoJogo`. Para evitar misturar jogos diferentes, ele só aceita um código de jogo base/atualização por vez.

## Continuar depois de erro ou cancelamento

O programa confere os arquivos que já existem antes de gravar:

- arquivo completo e igual ao conteúdo do PKG: é reaproveitado;
- arquivo ausente, incompleto ou diferente: é extraído novamente por inteiro;
- arquivo que falhou no meio: não é considerado concluído.

Por isso, se um PKG der erro, você pode selecionar outro pacote e extrair novamente sem repetir os pacotes que já terminaram corretamente.

O programa guarda um pequeno registro de retomada na pasta `.pkg-extractor` dentro do destino. Esse registro usa o tamanho e uma conferência do conteúdo do arquivo. Se o registro não puder ser lido, os arquivos existentes ainda são conferidos diretamente.

Cada arquivo é gravado primeiro em um temporário. Ele só substitui o arquivo final depois que a gravação e a conferência terminam. Isso protege arquivos já completos durante cancelamento, falta de espaço ou erro de leitura.

## Mensagens de erro comuns

### `compressed area (PFSC) not found`

PFSC é a área compactada que contém os dados do sistema de arquivos de muitos PKGs de jogo base e atualização.

Essa mensagem significa que o extrator precisava encontrar essa área, mas não encontrou. As causas mais comuns são:

- PKG incompleto ou copiado antes de terminar;
- formato diferente do compatível;
- PKG que não pertence à família fake PKG 5.05+;
- dados internos danificados.

Alguns DLCs pequenos contêm somente licença e metadados. Eles podem não ter uma área PFSC e, nesse caso, a ausência dessa área é normal.

Confira se o arquivo terminou de baixar ou copiar e tente novamente. Um erro em um PKG não impede a extração dos outros pacotes.

### `official encryption` ou `Criptografia oficial`

O programa identificou criptografia oficial da Sony, sem as chaves esperadas pelo formato compatível. Esse pacote é ignorado; ele não é convertido nem descriptografado pelo programa.

## Apagar os PKGs depois da extração

A opção **Delete .pkg files after successful extraction** vem desmarcada. Enquanto estiver desmarcada, os PKGs originais são mantidos.

Se for marcada, o programa só tenta apagar um `.pkg` depois que a extração daquele pacote termina com sucesso. Em caso de erro ou cancelamento, o original não é apagado.

Confirme sempre o resultado antes de usar essa opção, porque a exclusão do arquivo original não pode ser desfeita pelo programa.

## Linha de comando

Também é possível extrair um PKG sem abrir a janela:

```text
easy-pkg-extractor.exe --no-gui "arquivo.pkg" "pasta de saída"
```

Esse modo extrai o arquivo informado para a pasta indicada. Para o uso normal com vários PKGs, use a janela do programa.

## Arquivos temporários do executável

O executável de arquivo único pode criar pastas temporárias com nome parecido com `_MEI...` na pasta temporária do Windows enquanto está aberto. Elas são usadas apenas para carregar os componentes do programa e não são a pasta de saída dos jogos.

Normalmente essas pastas são removidas quando o programa fecha. Se o Windows encerrar o processo à força, uma pasta temporária pode permanecer; ela não contém os arquivos extraídos do jogo.

## Desempenho

O executável usa o mesmo código de leitura, descriptografia, descompressão e gravação do arquivo Python. A extração é feita diretamente no destino escolhido.

O verificador evita repetir arquivos que já foram extraídos corretamente, mas a primeira extração pode levar bastante tempo. O resultado depende principalmente do tamanho do PKG, da velocidade do disco, do processador e do antivírus.

## Requisitos

- Windows 64 bits.
- Espaço livre suficiente para os arquivos extraídos.
- Permissão para gravar na pasta de saída.
- PKGs completos e compatíveis com o formato explicado acima.

Não são distribuídos jogos, PKGs reais, saves, caches, launchers de terceiros ou arquivos retirados de jogos.

Use somente arquivos que você tem direito de utilizar. Este projeto não é afiliado à Sony, PlayStation, aos donos dos jogos ou aos seus desenvolvedores.

## Arquivos do projeto

Na área [Releases](https://github.com/gustasrod/easy-pkg-extractor/releases) está o executável pronto:

- `easy-pkg-extractor-windows-x64.zip`: pacote portátil para Windows 64 bits.

No código do projeto:

- `pkg_extractor.py`: código-fonte do programa;
- `README.md`: este manual;
- `docs/images/`: imagens usadas neste manual.

## Compilar o executável

Para gerar o executável a partir do código-fonte, use Python 3.12 ou mais recente:

```text
python -m pip install pycryptodome pyinstaller
pyinstaller --noconfirm --clean --onefile --windowed --name easy-pkg-extractor --distpath ".release\\onefile-dist" --workpath ".release\\build" --specpath ".release" pkg_extractor.py
```

O arquivo gerado será `easy-pkg-extractor.exe`. O ZIP de distribuição deve conter somente esse executável.

## Organização recomendada junto ao launcher

Deixe o programa na mesma pasta dos arquivos do launcher e guarde os PKGs em uma subpasta, como `.PKGs`. Ao abrir, o programa procura arquivos `.pkg` na pasta do executável e em todas as subpastas, sem precisar iniciar uma busca manual.

Para criar a pasta do jogo ao lado do executável e da pasta `.PKGs`, escolha como saída a própria pasta do launcher:

```text
Pasta do launcher
├─ easy-pkg-extractor.exe
├─ Launcher.exe e arquivos auxiliares
├─ .PKGs/
│  ├─ jogo-base.pkg
│  ├─ atualização.pkg
│  └─ dlc.pkg
└─ .NomeDoJogo/ (criada pelo programa na pasta de saída)
```

Os nomes dos arquivos `.pkg` são apenas exemplos. Se **Output folder** apontar para outro lugar, `.NomeDoJogo` será criada nessa outra pasta, não ao lado do executável.

![Exemplo da organização do programa, dos PKGs e da pasta do jogo](docs/images/exemplo-organizacao-launcher.png)

*A captura mostra o executável, a pasta `.PKGs` e a pasta do jogo no Explorer. O campo **Output folder** define onde uma nova extração será criada. Para deixá-la ao lado do executável, selecione a pasta do launcher como destino.*
