# ⚠️ Limitações no Pydroid 3

Esta biblioteca tem limitações significativas quando executada no **Pydroid 3** devido a restrições do ambiente:

## 1. **Processos Python**
- ❌ **Não funcionam** devido ao DRM do Pydroid
- ✅ Outros tipos de processo funcionam normalmente:
  - Outros interpretadores
  - Binários ELF
  - Shell scripts (sh, bash, etc.)

## 2. **Isolamento**
- ❌ Sem suporte a Firejail
- ⚠️ Apenas isolamento parcial disponível

## 3. **Problemas com Bibliotecas**
- O Pydroid não permite acesso aos Paths de bibliotecas do Android
- Apenas bibliotecas do próprio Pydroid estão disponíveis no `LD_LIBRARY_PATH`
- Isso pode causar falhas em processos que dependem de bibliotecas específicas

---

# ✅ Ambientes Recomendados

## Para Android (Alternativas):
1. **UserLAnd** - ⭐ **Recomendado**
2. **Termux** - Alternativa viável
3. **Andronix** - Outra alternativa

## Para Desktop:
- **Distribuições Linux** com suporte a:
  - Python 3
  - Firejail (para isolamento completo)
- **Exemplo**: Ubuntu e derivados

---

## 📝 Nota do Desenvolvedor
O desenvolvedor prefere não solucionar as limitações específicas do Pydroid 3, focando em ambientes que oferecem funcionalidades completas.
