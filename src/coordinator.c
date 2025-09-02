#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include "hash_utils.h"

/**
 * PROCESSO COORDENADOR - Mini-Projeto 1: Quebra de Senhas Paralelo
 * 
 * Este programa coordena múltiplos workers para quebrar senhas MD5 em paralelo.
 * O MD5 JÁ ESTÁ IMPLEMENTADO - você deve focar na paralelização (fork/exec/wait).
 * 
 * Uso: ./coordinator <hash_md5> <tamanho> <charset> <num_workers>
 * 
 * Exemplo: ./coordinator "900150983cd24fb0d6963f7d28e17f72" 3 "abc" 4
 * 
 * SEU TRABALHO: Implementar os TODOs marcados abaixo
 */

#define MAX_WORKERS 16
#define RESULT_FILE "password_found.txt"

/**
 * Calcula o tamanho total do espaço de busca
 * 
 * @param charset_len Tamanho do conjunto de caracteres
 * @param password_len Comprimento da senha
 * @return Número total de combinações possíveis
 */
long long calculate_search_space(int charset_len, int password_len) {
    long long total = 1;
    for (int i = 0; i < password_len; i++) {
        total *= charset_len;
    }
    return total;
}

/**
 * Converte um índice numérico para uma senha
 * Usado para definir os limites de cada worker
 * 
 * @param index Índice numérico da senha
 * @param charset Conjunto de caracteres
 * @param charset_len Tamanho do conjunto
 * @param password_len Comprimento da senha
 * @param output Buffer para armazenar a senha gerada
 */
void index_to_password(long long index, const char *charset, int charset_len, 
                       int password_len, char *output) {
    for (int i = password_len - 1; i >= 0; i--) {
        output[i] = charset[index % charset_len];
        index /= charset_len;
    }
    output[password_len] = '\0';
}

/**
 * Função principal do coordenador
 */
int main(int argc, char *argv[]) {

    // TODO 1: Validar argumentos de entrada
    // Verificar se argc == 5 (programa + 4 argumentos)
    // Se não, imprimir mensagem de uso e sair com código 1
    if (argc != 5){
        fprintf(stderr,"Uso: %s <hash_md5> <tamanho> <charset> <num_workers>\n",argv[0]);
        return 1;
    }
    
    // Parsing dos argumentos (após validação)
    const char *target_hash = argv[1];
    int password_len = atoi(argv[2]);
    const char *charset = argv[3];
    int num_workers = atoi(argv[4]);
    int charset_len = strlen(charset);
    
    // TODO: Adicionar validações dos parâmetros
    // - password_len deve estar entre 1 e 10
    if (password_len <1 || password_len > 10){
        printf("Erro: senha deve ter tamanho entre 1 e 10\n");
        return 1;
    }

    // - num_workers deve estar entre 1 e MAX_WORKERS
    if (num_workers < 1 || num_workers > MAX_WORKERS){
        printf("Erro: número de workers deve estar entre 1 e %d\n", MAX_WORKERS);
        return 1;
    }

    // - charset não pode ser vazio
    if (charset_len <= 0){
        printf("Erro: número de caracteres deve ser maior que 0\n");
        return 1;
    }
    
    printf("=== Mini-Projeto 1: Quebra de Senhas Paralelo ===\n");
    printf("Hash MD5 alvo: %s\n", target_hash);
    printf("Tamanho da senha: %d\n", password_len);
    printf("Charset: %s (tamanho: %d)\n", charset, charset_len);
    printf("Número de workers: %d\n", num_workers);
    
    // Calcular espaço de busca total
    long long total_space = calculate_search_space(charset_len, password_len);
    printf("Espaço de busca total: %lld combinações\n\n", total_space);
    
    // Remover arquivo de resultado anterior se existir
    unlink(RESULT_FILE);
    
    // Registrar tempo de início
    time_t start_time = time(NULL);
    
    // TODO 2: Dividir o espaço de busca entre os workers
    // Calcular quantas senhas cada worker deve verificar
    // DICA: Use divisão inteira e distribua o resto entre os primeiros workers
    long long passwords_per_worker = total_space/ num_workers;
    long long remaining = total_space % num_workers;
    
    // Arrays para armazenar PIDs dos workers
    pid_t workers[MAX_WORKERS];
    
    // TODO 3: Criar os processos workers usando fork()
    printf("Iniciando workers...\n");
    
    // IMPLEMENTE AQUI: Loop para criar workers
    for (int i = 0; i < num_workers; i++) {
        // TODO: Calcular intervalo de senhas para este worker
        long long primeiro_num = i * (total_space / num_workers);
        long long ultimo_num   = (i == num_workers - 1) ? total_space - 1 : (primeiro_num + (total_space / num_workers) - 1);

        // TODO: Converter indices para senhas de inicio e fim
        char primeira_senha[11], ultima_senha[11];
        index_to_password(primeiro_num, charset, charset_len, password_len, primeira_senha);
        index_to_password(ultimo_num,   charset, charset_len, password_len, ultima_senha);

        // TODO 4: Usar fork() para criar processo pid
        pid_t pid = fork();

        if (pid < 0) {
            fprintf(stderr, "Erro ao criar worker %d\n", i);
            continue;
        }

        
        // TODO 6: No processo pid: usar execl() para executar worker
        if (pid == 0) {
            char id_worker[10], tam_senha[10];
            sprintf(id_worker, "%d", i);
            sprintf(tam_senha, "%d", password_len);
            
            execl("./worker", "worker", target_hash, primeira_senha, ultima_senha, charset, tam_senha, id_worker, (char *)NULL);
            
            // TODO 7: Tratar erros de fork() e execl()
            perror("Erro no execl");
            exit(1);
        }
        // TODO 5: No processo pai: armazenar PID
        else {
            workers [i] = pid;
        }
    }

    
    printf("\nTodos os workers foram iniciados. Aguardando conclusão...\n");
    
    // TODO 8: Aguardar todos os workers terminarem usando wait()
    // IMPORTANTE: O pai deve aguardar TODOS os filhos para evitar zumbis
    
    // IMPLEMENTE AQUI:
    // - Loop para aguardar cada worker terminar
    int workersTerminados = 0; 
    while (workersTerminados < num_workers){
        int status;
        // - Usar wait() para capturar status de saída
        pid_t pid = wait(&status);

        // - Identificar qual worker terminou
        if (status == 0) {
            printf("Worker (PID %d) terminou normalmente.\n", pid);
        }
        // - Verificar se terminou normalmente ou com erro
        else{
            printf("Worker (PID %d) terminou com erro.\n", pid);
        }

        // - Contar quantos workers terminaram
        workersTerminados++;
    }
    
    // Registrar tempo de fim
    time_t end_time = time(NULL);
    double elapsed_time = difftime(end_time, start_time);
    
    printf("\n=== Resultado ===\n");
    
    // TODO 9: Verificar se algum worker encontrou a senha
    // Ler o arquivo password_found.txt se existir
    
    // IMPLEMENTE AQUI:
    FILE *fp = fopen(RESULT_FILE, "r");

    // - Ler conteúdo do arquivo
    if (fp) {
    char line[256];
    if (fgets(line, sizeof(line), fp) != NULL) {
        // - Fazer parse do formato "worker_id:password"
        char *separador = strchr(line, ':');
        if (separador) {
            *separador = '\0';
            const char *id_str = line;
            char *pwd = separador + 1;

            char hash_out[33] = {0};
            // - Verificar o hash usando md5_string()
            md5_string(pwd, hash_out);

            // - Exibir resultado encontrado
            printf("Worker %s encontrou senha \"%s\".\n", id_str, pwd);
            }
    }
    fclose(fp);
    } 
    else {
    printf("Nenhum worker reportou senha (arquivo não existe).\n");
    }
    
    // Estatísticas finais (opcional)
    // TODO: Calcular e exibir estatísticas de performance
    
    return 0;