# Easy PKG Extractor

Extrator e organizador de arquivos `.pkg` para Windows. O programa foi pensado para facilitar o uso de PKGs encontrados em portes recentes de jogos para PC: coloque o programa na pasta do launcher, clique para procurar os arquivos e extraia tudo de forma organizada.

## Uso rápido

1. Baixe `easy-pkg-extractor-windows-x64.zip` na área **Releases**.
2. Extraia `easy-pkg-extractor.exe` para a pasta do launcher ou para a pasta que contém os arquivos `.pkg`.
3. Abra o executável.
4. Clique em **Search .pkg in this folder** para procurar os PKGs da pasta e das subpastas.
5. Deixe **All packages in the list** marcado ou escolha **Only selected packages** e selecione os PKGs desejados na lista.
6. Clique em **Extract and Organize**.

Não é necessário instalar Python. O executável já contém os componentes necessários.

O idioma inicial é inglês. O botão no canto superior esquerdo alterna entre inglês e português.

## O que o programa faz

- Procura arquivos `.pkg` na pasta do programa e nas subpastas.
- Identifica jogo base, atualização e DLC pelas informações internas do pacote.
- Mostra status, tipo, título, código, versão, tamanho e nome do arquivo.
- Extrai PKGs compatíveis com o formato fake 5.05+ e suas áreas PFSC.
- Permite escolher quais PKGs serão extraídos. A seleção é do pacote inteiro, não de arquivos internos.
- Junta jogo base e atualização na mesma pasta quando essa opção está ativa.
- Mantém os DLCs separados dentro de `addcont`.
- Permite escolher outra pasta de saída ou extrair diretamente na pasta do programa.
- Permite cancelar sem apagar o que já foi concluído.
- Pode apagar os arquivos `.pkg` somente quando essa opção for marcada.

## Organização padrão

O destino padrão usa o nome identificado no PKG do jogo base, com um ponto no início:

```text
.NomeDoJogo\\
├─ CUSAxxxxx\\
├─ CUSAxxxxx-patch\\
└─ addcont\\
   └─ CUSAxxxxx\\
      └─ ID_DO_DLC\\
```

Com **Juntar jogo e atualização** ativado, que é a opção padrão, o jogo base e a atualização ficam juntos dentro de `CUSAxxxxx`. Nesse caso, a pasta `CUSAxxxxx-patch` não é criada. As atualizações são aplicadas na ordem da versão mais antiga para a mais nova.

Se **Juntar jogo e atualização** for desativado, a atualização fica separada em `CUSAxxxxx-patch`, como no exemplo acima. Cada DLC continua dentro de `addcont\\CUSAxxxxx\\ID_DO_DLC`.

Também é possível escolher outra pasta de saída ou marcar **Extract in program folder**. Nesse caso, o resultado fica ao lado do executável.

## Retomada após erro

Antes de extrair, o programa verifica o que já existe no destino. Arquivos completos e iguais são reaproveitados. Arquivos ausentes, incompletos ou diferentes são extraídos novamente por inteiro.

Isso permite selecionar outro PKG e continuar depois de um erro sem repetir a extração dos pacotes que já terminaram. O programa também registra informações de retomada na pasta `.pkg-extractor`.

Cada arquivo é gravado primeiro em um temporário. O arquivo final só é substituído quando a gravação termina e a conferência passa. Assim, um arquivo bom não é trocado por um arquivo incompleto durante cancelamento, falta de espaço ou erro de leitura.

## Erro de PFSC

Se aparecer:

```text
compressed area (PFSC) not found
```

o PKG não possui a área compactada esperada pelo extrator. As causas mais comuns são formato diferente do compatível, arquivo incompleto ou PKG que não é fake 5.05+.

Nesse caso, confira se o PKG terminou de baixar ou copiar e tente outro pacote. O erro em um PKG não impede que os outros sejam extraídos separadamente.

## Linha de comando

Também é possível extrair sem abrir a janela:

```text
easy-pkg-extractor.exe --no-gui "arquivo.pkg" "pasta de saída"
```

Esse modo é opcional. Para o uso normal, basta deixar o executável junto dos PKGs e usar a janela do programa.

## Desempenho

O executável usa o mesmo código de leitura, descriptografia, descompressão e gravação do arquivo Python. A extração é feita diretamente para a pasta escolhida, e o verificador de arquivos evita repetir o trabalho que já terminou corretamente.

O tempo depende do tamanho do PKG, do disco, do processador e do antivírus. A primeira extração pode levar bastante tempo; nas tentativas seguintes, arquivos completos são reaproveitados.

## Requisitos

- Windows 64 bits.
- Espaço livre suficiente para os arquivos extraídos.
- Permissão para gravar na pasta de saída.
- PKGs completos e em formato compatível.

Não são distribuídos jogos, PKGs reais, saves, caches, launchers de terceiros ou arquivos retirados de jogos.

Use somente arquivos que você tem direito de utilizar. Este projeto não é afiliado à Sony, PlayStation, aos donos dos jogos ou aos seus desenvolvedores.

## Arquivos disponíveis

Na área **Releases**:

- `easy-pkg-extractor-windows-x64.zip`: executável portátil para Windows 64 bits.

No código do projeto:

- `pkg_extractor.py`: código-fonte do programa.
- `README.md`: este manual.

## Compilação

Para gerar o executável a partir do código-fonte, use Python 3.12 ou mais recente:

```text
python -m pip install pycryptodome pyinstaller
pyinstaller --noconfirm --clean --onefile --windowed --name easy-pkg-extractor --distpath ".release\\onefile-dist" --workpath ".release\\build" --specpath ".release" pkg_extractor.py
```

O arquivo gerado será `easy-pkg-extractor.exe`. O ZIP de distribuição deve conter somente esse executável.
