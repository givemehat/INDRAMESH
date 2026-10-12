import torch
from torch.utils.data import Dataset
import pandas as pd
import javalang

class CryptoMultiModalDataset(Dataset):
    def __init__(self, csv_file, vocab=None, max_seq_len=200):
        self.df = pd.read_csv(csv_file).dropna()
        
        # Filter rare classes
        class_counts = self.df['label'].value_counts()
        valid_classes = class_counts[class_counts >= 3].index
        self.df = self.df[self.df['label'].isin(valid_classes)]
        self.df.reset_index(drop=True, inplace=True)
        
        self.max_seq_len = max_seq_len
        self.labels = self.df['label'].unique().tolist()
        self.label_to_idx = {l: i for i, l in enumerate(self.labels)}
        
        # Build vocabulary based on character tokens
        if vocab is None:
            chars = set()
            for code in self.df['code']:
                chars.update(list(code))
            self.vocab = {c: i+1 for i, c in enumerate(sorted(chars))} # 0 is padding
            self.vocab['<UNK>'] = len(self.vocab) + 1
        else:
            self.vocab = vocab
            
        self.vocab_size = len(self.vocab) + 1
        
    def __len__(self):
        return len(self.df)
        
    def _extract_ast_features(self, code):
        """
        Modality 2: Structural / Static handcrafted features using Abstract Syntax Tree (AST)
        """
        # Baseline features
        features = [
            1.0 if 'import ' in code else 0.0,
            1.0 if 'new ' in code else 0.0,
            1.0 if 'getInstance' in code else 0.0,
            1.0 if 'generate' in code else 0.0,
            1.0 if 'SecretKey' in code else 0.0,
            code.count('(') / 10.0,
            code.count('"') / 10.0,
            len(code) / 500.0,
            0.0, # AST Depth
            0.0, # Number of Methods
            0.0, # Number of Local Variables
            0.0  # Number of TryCatches (Security checks)
        ]
        
        # Advanced: Attempt to parse AST using javalang
        try:
            # Wrap code in class/method if it's a raw snippet to make it valid Java syntax
            if "class " not in code:
                java_code = f"class Wrapper {{ void method() {{ {code} }} }}"
            else:
                java_code = code
                
            tree = javalang.parse.parse(java_code)
            
            methods_count = len(list(tree.filter(javalang.tree.MethodDeclaration)))
            local_vars_count = len(list(tree.filter(javalang.tree.LocalVariableDeclaration)))
            try_catches_count = len(list(tree.filter(javalang.tree.TryStatement)))
            
            # Simple depth calculation
            depths = []
            for path, node in tree:
                depths.append(len(path))
            max_depth = max(depths) if depths else 0
            
            features[8] = max_depth / 20.0
            features[9] = methods_count / 5.0
            features[10] = local_vars_count / 10.0
            features[11] = try_catches_count / 5.0
            
        except Exception:
            # Fallback if AST parsing fails
            pass
            
        return torch.tensor(features, dtype=torch.float)
        
    def _tokenize(self, code):
        """
        Modality 1: Semantic sequence of the code
        """
        tokens = [self.vocab.get(c, self.vocab['<UNK>']) for c in list(code)]
        if len(tokens) > self.max_seq_len:
            tokens = tokens[:self.max_seq_len]
        else:
            tokens += [0] * (self.max_seq_len - len(tokens)) # Padding
        return torch.tensor(tokens, dtype=torch.long)
        
    def __getitem__(self, idx):
        code = str(self.df.iloc[idx]['code'])
        label_str = self.df.iloc[idx]['label']
        
        seq_features = self._tokenize(code)
        static_features = self._extract_ast_features(code)
        label = torch.tensor(self.label_to_idx[label_str], dtype=torch.long)
        
        return seq_features, static_features, label
